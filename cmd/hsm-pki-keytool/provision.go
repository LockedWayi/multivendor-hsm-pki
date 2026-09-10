package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/config"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/signingkey"
)

// runProvisionSigningKeyCmd provisions one supply-chain signing key on the
// token the operator names, and writes out the public half.
//
// One key per invocation. Generation is irreversible, so a single run
// that created the image key and then failed on the artifact key would
// leave half a result and a taken label.
//
// The PIN does not go through config.ResolvePIN. config.Config describes
// the service's single token, and reaching this token through it would
// let the service's configuration name the supply-chain token. pinResolver
// reads the PIN at the point of use and LoginToken wraps it in
// pkcs11.SecurePIN.
func runProvisionSigningKeyCmd(args []string) error {
	fs := flag.NewFlagSet("provision-signing-key", flag.ExitOnError)

	adapterName := fs.String("adapter", config.AdapterSoftHSM2, "vendor adapter: \"softhsm2\" or \"protectserver\"")
	modulePath := fs.String("module", "", "path to the PKCS#11 module (.so)")
	curveName := fs.String("curve", "P-256", "EC curve for the key pair: P-256, P-384, or P-521")

	workspaceLabel := fs.String("workspace", "", "token label the signing key is generated on; the supply-chain token, never the CA's")
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
	// Everything checkable without the token is checked first. The label
	// rule is signingkey's.
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
	// The public key is written before the error is checked.
	// provisionSigningKey can return a usable key with a teardown error,
	// and the key pair cannot be regenerated because its label is taken.
	if key.Public != nil {
		if err := writePublicKeyPEM(*publicKeyOut, key); err != nil {
			return err
		}
		fmt.Printf("signing key provisioned:\n  token:      %s (serial %s)\n  label:      %s\n  curve:      %s\n  public key: %s\n",
			ws.Label, ws.Serial, key.Label, *curveName, *publicKeyOut)
		// Read back off the token, not assumed from the template.
		fmt.Printf("token reports CKA_SENSITIVE=%t CKA_EXTRACTABLE=%t; the private key stays on the token\n",
			key.Sensitive, key.Extractable)
	}
	if provisionErr != nil {
		return provisionErr
	}
	return nil
}

// provisionSigningKey holds the token's login for one provisioning and
// gives it back afterwards, on every path. It may return a valid Key with
// a non-nil error: a failed logout does not un-generate the key pair.
func provisionSigningKey(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, resolvePIN func() ([]byte, error), params signingkey.Params) (key signingkey.Key, err error) {
	if adapter.TokenLoggedIn() {
		return signingkey.Key{}, fmt.Errorf("a token is already authenticated before logging into %q; refusing to proceed", ws.Label)
	}
	pin, err := resolvePIN()
	if err != nil {
		return signingkey.Key{}, fmt.Errorf("resolving PIN for %q: %w", ws.Label, err)
	}
	// LoginToken zeroes pin.
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

	// Checked before anything is generated: this must not be the CA's token.
	if err := signingkey.CheckNoCAHierarchyKey(ctx, adapter, s); err != nil {
		return signingkey.Key{}, err
	}

	return signingkey.Provision(ctx, adapter, s, params)
}

// writePublicKeyPEM writes the public half as PKIX PEM, mode 0644. On a
// write failure the PEM is printed to stdout: the key pair exists on the
// token and its label cannot be reused.
func writePublicKeyPEM(path string, key signingkey.Key) error {
	pemBytes, err := key.PEM()
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, pemBytes, 0644); err != nil {
		fmt.Printf("could not write %s, so the public key follows on stdout; the key pair exists on the token and its label cannot be reused:\n%s", path, pemBytes)
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}
