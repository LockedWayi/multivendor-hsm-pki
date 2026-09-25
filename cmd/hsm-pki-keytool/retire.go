package main

import (
	"context"
	"crypto/ecdsa"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/config"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/inventory"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/signingkey"
)

// runRetireSigningKeyCmd destroys one supply-chain signing key on its
// token: the irreversible last step of a rotation, after the next version
// has taken over and the transition window has closed.
//
// Retirement follows the inventory rather than the other way round. The
// command takes the current published document and refuses unless it
// lists the label as verify-only. An active key is not retired, it is
// rotated first. A key the document never listed is not retired, it is
// removed, and that is not this command's job. A key the document already
// calls retired should not be on the token at all; finding it there means
// the document is wrong, and destroying the key by hand would not make it
// right.
//
// A label is addressing, not identity. Before anything is destroyed, the
// public key under that label on the token is compared with the one the
// inventory lists, and a mismatch is refused: the object on the token is
// not the key the document is talking about.
//
// The inventory's signature is not checked here. The operator holding the
// token's PIN is inside the trust boundary that produces the document, and
// generate-inventory -in reads it the same way.
func runRetireSigningKeyCmd(args []string) error {
	fs := flag.NewFlagSet("retire-signing-key", flag.ExitOnError)

	adapterName := fs.String("adapter", pk11.AdapterSoftHSM2, pk11.AdapterFlagUsage)
	modulePath := fs.String("module", "", "path to the PKCS#11 module (.so)")

	workspaceLabel := fs.String("workspace", "", "token label holding the key; the supply-chain token")
	workspaceSerial := fs.String("workspace-serial", "", "token serial number, to disambiguate when several tokens share the label")
	pinEnv := fs.String("pin-env", "", "environment variable holding the token's PIN")
	keyLabel := fs.String("key-label", "", "versioned CKA_LABEL of the key to destroy (e.g. image-signing-key-v1)")
	inventoryPath := fs.String("inventory", "", "the current published key inventory; the key must be listed there as verify-only")

	if err := fs.Parse(args); err != nil {
		return err
	}
	for name, v := range map[string]string{
		"-module": *modulePath, "-workspace": *workspaceLabel, "-pin-env": *pinEnv,
		"-key-label": *keyLabel, "-inventory": *inventoryPath,
	} {
		if v == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	// Everything checkable without the token is checked first. Destruction
	// cannot be undone, so a refusal has to come before the login.
	if err := signingkey.ValidateLabel(*keyLabel); err != nil {
		return err
	}
	entry, err := retirableEntry(*inventoryPath, *keyLabel)
	if err != nil {
		return err
	}
	curve, err := config.ParseCurve(entry.Curve)
	if err != nil {
		return fmt.Errorf("the inventory lists %q on curve %q: %w", *keyLabel, entry.Curve, err)
	}
	listed, err := entry.PublicKey()
	if err != nil {
		return err
	}

	adapter, err := pk11.NewAdapterByName(*adapterName, *modulePath)
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

	destroyed, err := retireSigningKey(ctx, adapter, ws, pinResolver(*pinEnv), *keyLabel, curve, listed)
	if err != nil {
		return err
	}
	fmt.Printf("signing key retired:\n  token:   %s (serial %s)\n  label:   %s\n  private: %s\n  public:  %s\n",
		ws.Label, ws.Serial, *keyLabel, halfWord(destroyed.Private), halfWord(destroyed.Public))
	fmt.Printf("The key can no longer sign. Republish the inventory so the document says so:\n"+
		"  hsm-pki-keytool generate-inventory -in %s ... -key %s:%s:retired ...\n",
		*inventoryPath, entry.Purpose, *keyLabel)
	return nil
}

func halfWord(destroyed bool) string {
	if destroyed {
		return "destroyed"
	}
	return "was not on the token"
}

// retirableEntry reads the inventory and returns the entry for label only
// when the document says the key may be retired now.
func retirableEntry(path, label string) (inventory.Entry, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return inventory.Entry{}, fmt.Errorf("reading the inventory %s: %w", path, err)
	}
	inv, err := inventory.Parse(data)
	if err != nil {
		return inventory.Entry{}, fmt.Errorf("parsing the inventory %s: %w", path, err)
	}
	for _, e := range inv.Keys {
		if e.Label != label {
			continue
		}
		switch e.Status {
		case inventory.StatusVerifyOnly:
			return e, nil
		case inventory.StatusActive:
			return inventory.Entry{}, fmt.Errorf("%q is listed as active in %s: an active key is rotated, not retired. "+
				"Provision the next version and republish the inventory with this one verify-only first", label, path)
		case inventory.StatusRetired:
			return inventory.Entry{}, fmt.Errorf("%q is already listed as retired in %s, so it should no longer be on the token. "+
				"If it is, the document is wrong, and destroying the key by hand would not make it right", label, path)
		default:
			// Parse validates every status, so this is unreachable; it is
			// a refusal rather than a fall-through all the same.
			return inventory.Entry{}, fmt.Errorf("%q has status %q in %s, which this command does not know how to retire", label, e.Status, path)
		}
	}
	return inventory.Entry{}, fmt.Errorf("%q is not listed in %s: a key the inventory never vouched for is not retired, "+
		"it is removed, and that is ci/token-cleanup's job", label, path)
}

// retireSigningKey holds the token's login for one destruction and gives
// it back afterwards, on every path. The private half goes first, so a
// failure part-way leaves a key that cannot sign rather than one that can.
func retireSigningKey(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, resolvePIN func() ([]byte, error), label string, curve pk11.ECCurve, listed *ecdsa.PublicKey) (destroyed signingkey.Destroyed, err error) {
	if adapter.TokenLoggedIn() {
		return signingkey.Destroyed{}, fmt.Errorf("a token is already authenticated before logging into %q; refusing to proceed", ws.Label)
	}
	pin, err := resolvePIN()
	if err != nil {
		return signingkey.Destroyed{}, fmt.Errorf("resolving PIN for %q: %w", ws.Label, err)
	}
	// LoginToken zeroes pin.
	if err := adapter.LoginToken(ctx, ws, pin, pk11.RoleUser); err != nil {
		return signingkey.Destroyed{}, fmt.Errorf("logging into %q: %w", ws.Label, err)
	}
	defer func() {
		logoutErr := adapter.LogoutToken(ctx)
		if logoutErr != nil && err == nil {
			err = fmt.Errorf("key %q was destroyed but logging out of %q failed: %w", label, ws.Label, logoutErr)
		}
	}()

	s, err := adapter.OpenSession(ctx, ws, pk11.DefaultSessionOptions())
	if err != nil {
		return signingkey.Destroyed{}, fmt.Errorf("opening a session on %q: %w", ws.Label, err)
	}
	defer func() {
		closeErr := adapter.CloseSession(ctx, s)
		if closeErr != nil && err == nil {
			err = fmt.Errorf("key %q was destroyed but closing the session failed: %w", label, closeErr)
		}
	}()

	// Load, not Verify: a key on its way out need not pass the protection
	// check, and refusing to destroy a key because it is extractable would
	// keep the wrong key alive.
	onToken, err := signingkey.Load(ctx, adapter, s, label, curve)
	if err != nil {
		return signingkey.Destroyed{}, fmt.Errorf("reading %q off token %q: %w", label, ws.Label, err)
	}
	if !signingkey.SameKey(onToken.Public, listed) {
		return signingkey.Destroyed{}, fmt.Errorf("the key under label %q on token %q is not the key the inventory lists under that label; "+
			"refusing to destroy a key the document is not talking about", label, ws.Label)
	}
	return signingkey.Destroy(ctx, adapter, s, label)
}
