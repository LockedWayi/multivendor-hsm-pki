package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/LockedWayi/hsm-pki-platform/internal/config"
	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
	"github.com/LockedWayi/hsm-pki-platform/internal/signingkey"
)

// runProvisionSigningKeyCmd provisions one supply-chain signing key —
// `image-signing-key-v1`, `artifact-signing-key-v1`, and their later
// versions — on the token the operator names, and writes out the public
// half so a verifier never needs the HSM (Phase 4.8).
//
// # One key per invocation
//
// The two keys this phase creates are provisioned by running this twice
// rather than by one command that makes both. Generation is irreversible:
// a single run that created the image key and then failed on the artifact
// key would leave an operator holding half a result and a taken label, and
// the recovery for that is a manual cleanup on a token. One key per run
// makes the unit of failure the same as the unit of work.
//
// # Why this does not go through config.ResolvePIN
//
// Phase 4's sub-task list says the PIN arrives via `config.ResolvePIN`.
// That was written before Phase 4.8 decided these keys live on a *third*
// token, and the two do not fit together: `config.Config` describes the
// online service's single token, and reaching this token through that type
// would mean the service's configuration schema gaining the ability to name
// the supply-chain token — the same thing internal/config's CAConfig
// deliberately cannot do for the root. The rule the sub-task is protecting
// is that there is exactly one PIN-handling implementation, and that holds
// here: the PIN is read from a named environment variable at the point of
// use by pinResolver (shared with the ceremony command, one line above this
// one in main.go), handed straight to adapter.LoginToken, and wrapped in
// pkcs11.SecurePIN there. No PIN value is stored, logged, or passed on a
// command line (CLAUDE.md §3.1).
func runProvisionSigningKeyCmd(args []string) error {
	fs := flag.NewFlagSet("provision-signing-key", flag.ExitOnError)

	adapterName := fs.String("adapter", config.AdapterSoftHSM2, "vendor adapter: \"softhsm2\" or \"protectserver\"")
	modulePath := fs.String("module", "", "path to the PKCS#11 module (.so)")
	curveName := fs.String("curve", "P-256", "EC curve for the key pair: P-256, P-384, or P-521")

	workspaceLabel := fs.String("workspace", "", "token label the signing key is generated on — the supply-chain token, never the CA's")
	workspaceSerial := fs.String("workspace-serial", "", "token serial number, to disambiguate when several tokens share the label")
	pinEnv := fs.String("pin-env", "", "environment variable holding the token's PIN")
	keyLabel := fs.String("key-label", "", "versioned CKA_LABEL for the key pair (e.g. image-signing-key-v1)")
	publicKeyOut := fs.String("public-key-out", "", "path to write the public key PEM")

	if err := fs.Parse(args); err != nil {
		return err
	}

	curve, err := config.ParseCurve(*curveName)
	if err != nil {
		return err
	}
	for name, v := range map[string]string{
		"-module": *modulePath, "-workspace": *workspaceLabel, "-pin-env": *pinEnv,
		"-key-label": *keyLabel, "-public-key-out": *publicKeyOut,
	} {
		if v == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	// Everything checkable without the token is checked before the token is
	// touched (CLAUDE.md §3.9). The label shape is signingkey's rule, not
	// this command's, so it is asked rather than restated — a second copy of
	// the pattern here would be a second place for it to drift.
	if err := signingkey.ValidateLabel(*keyLabel); err != nil {
		return err
	}
	if _, err := os.Stat(*publicKeyOut); err == nil {
		return fmt.Errorf("refusing to overwrite existing file %s", *publicKeyOut)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("checking output path %s: %w", *publicKeyOut, err)
	}

	adapter, err := newVendorAdapter(*adapterName, *modulePath)
	if err != nil {
		return err
	}
	defer adapter.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	ws, err := findWorkspace(ctx, adapter, *workspaceLabel, *workspaceSerial)
	if err != nil {
		return err
	}

	key, provisionErr := provisionSigningKey(ctx, adapter, ws, pinResolver(*pinEnv), signingkey.Params{
		Label: *keyLabel,
		Curve: curve,
	})
	// The public key is written before the error is checked, for the same
	// reason the ceremony writes its certificates first: provisionSigningKey
	// can return a usable key alongside a teardown error, and the key pair
	// it describes cannot be regenerated because its label is now taken
	// (CLAUDE.md §3.9). Discarding the public half would leave an operator
	// with a key on a token and no published way to verify anything it signs.
	if key.Public != nil {
		if err := writePublicKeyPEM(*publicKeyOut, key); err != nil {
			return err
		}
		fmt.Printf("signing key provisioned:\n  token:      %s (serial %s)\n  label:      %s\n  curve:      %s\n  public key: %s\n",
			ws.Label, ws.Serial, key.Label, *curveName, *publicKeyOut)
		// Reported because they were read back off the token rather than
		// assumed from the template that asked for them — the distinction
		// this platform has paid to learn twice (docs/lessons.md §1, §6).
		fmt.Printf("token reports CKA_SENSITIVE=%t CKA_EXTRACTABLE=%t — the private key stays on the token\n",
			key.Sensitive, key.Extractable)
	}
	if provisionErr != nil {
		return provisionErr
	}
	return nil
}

// provisionSigningKey holds the token's login for the span of one
// provisioning and gives it back afterwards, on every path.
//
// It may return a valid Key alongside a non-nil error: a logout or session
// close that fails after the key pair was generated does not un-generate it,
// and the caller needs the public half more than it needs a tidy signature
// (CLAUDE.md §3.9). The ceremony's withTokenLogin makes the same trade for
// the same reason.
func provisionSigningKey(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, resolvePIN func() ([]byte, error), params signingkey.Params) (key signingkey.Key, err error) {
	if adapter.TokenLoggedIn() {
		return signingkey.Key{}, fmt.Errorf("a token is already authenticated before logging into %q — refusing to proceed", ws.Label)
	}
	pin, err := resolvePIN()
	if err != nil {
		return signingkey.Key{}, fmt.Errorf("resolving PIN for %q: %w", ws.Label, err)
	}
	// LoginToken consumes and zeroes pin, and is the only place a PIN value
	// reaches a PKCS#11 call in this repository (internal/pkcs11.SecurePIN).
	if err := adapter.LoginToken(ctx, ws, pin, pk11.RoleUser); err != nil {
		return signingkey.Key{}, fmt.Errorf("logging into %q: %w", ws.Label, err)
	}
	defer func() {
		logoutErr := adapter.LogoutToken(ctx)
		if logoutErr != nil && err == nil {
			err = fmt.Errorf("key %q was provisioned but logging out of %q failed (the returned key is valid and must not be discarded): %w",
				params.Label, ws.Label, logoutErr)
		}
	}()

	s, err := adapter.OpenSession(ctx, ws, pk11.DefaultSessionOptions())
	if err != nil {
		return signingkey.Key{}, fmt.Errorf("opening a session on %q: %w", ws.Label, err)
	}
	defer func() {
		closeErr := adapter.CloseSession(ctx, s)
		if closeErr != nil && err == nil {
			err = fmt.Errorf("key %q was provisioned but closing the session failed (the returned key is valid and must not be discarded): %w",
				params.Label, closeErr)
		}
	}()

	// Before anything is generated, and therefore while the answer can still
	// change the outcome: this must not be the CA's token.
	if err := signingkey.CheckNoCAHierarchyKey(ctx, adapter, s); err != nil {
		return signingkey.Key{}, err
	}

	return signingkey.Provision(ctx, adapter, s, params)
}

// writePublicKeyPEM writes the public half as PKIX PEM. Mode 0644: this is
// the artifact every verifier needs and no verifier needs a secret, which
// is the property that makes an HSM-held signing key worth having.
//
// On a write failure the PEM is printed to stdout rather than lost. The key
// pair exists on the token by this point and its label cannot be reused, so
// an operator who has just filled a disk must still be able to recover the
// only public artifact of an irreversible operation.
func writePublicKeyPEM(path string, key signingkey.Key) error {
	pemBytes, err := key.PEM()
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, pemBytes, 0644); err != nil {
		fmt.Printf("could not write %s, so the public key follows on stdout — the key pair exists on the token and its label cannot be reused:\n%s", path, pemBytes)
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
