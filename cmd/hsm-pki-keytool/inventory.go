package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/config"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/inventory"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/signingkey"
)

// keySpec is one `purpose:label:status` triple from the command line.
type keySpec struct {
	purpose inventory.Purpose
	label   string
	status  inventory.Status
}

// keySpecs collects the repeatable -key flag.
type keySpecs []keySpec

func (k *keySpecs) String() string { return fmt.Sprintf("%d keys", len(*k)) }

// Set parses purpose:label:status. All three are required: a status this
// tool guessed would be a lifecycle decision made by a default.
func (k *keySpecs) Set(v string) error {
	parts := strings.Split(v, ":")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return fmt.Errorf("want purpose:label:status (e.g. image:image-signing-key-v1:active), got %q", v)
	}
	*k = append(*k, keySpec{
		purpose: inventory.Purpose(parts[0]),
		label:   parts[1],
		status:  inventory.Status(parts[2]),
	})
	return nil
}

// runGenerateInventoryCmd builds and signs the key inventory from the keys
// on the token. A hand-maintained inventory drifts from the token after a
// rotation. Every live entry is read off the token through
// signingkey.Verify, so a key the token reports as extractable never
// reaches the published list.
//
// The supply-chain token holds the keys being listed; the offline token
// holds the inventory signing key. If those were one token, anyone holding
// it could add their own key to the list. The command refuses until it has
// measured that they differ: by serial, and then by confirming the
// inventory signing key is not findable from the supply-chain token.
func runGenerateInventoryCmd(args []string) error {
	fs := flag.NewFlagSet("generate-inventory", flag.ExitOnError)

	adapterName := fs.String("adapter", config.AdapterSoftHSM2, "vendor adapter: \"softhsm2\" or \"protectserver\"")
	modulePath := fs.String("module", "", "path to the PKCS#11 module (.so)")
	curveName := fs.String("curve", "P-256", "EC curve the listed keys were generated on: P-256, P-384, or P-521")

	workspaceLabel := fs.String("workspace", "", "token label holding the supply-chain signing keys")
	workspaceSerial := fs.String("workspace-serial", "", "token serial number, to disambiguate when several tokens share the label")
	pinEnv := fs.String("pin-env", "", "environment variable holding the supply-chain token's PIN")

	invWorkspaceLabel := fs.String("inventory-workspace", "", "token label holding the inventory signing key; the offline token, never the one above")
	invWorkspaceSerial := fs.String("inventory-workspace-serial", "", "token serial number for the inventory signing token")
	invPINEnv := fs.String("inventory-pin-env", "", "environment variable holding the inventory signing token's PIN")
	invKeyLabel := fs.String("inventory-key-label", "", "versioned CKA_LABEL of the inventory signing key (e.g. inventory-signing-key-v1)")

	var keys keySpecs
	fs.Var(&keys, "key", "a key to list, as purpose:label:status (repeatable); e.g. image:image-signing-key-v1:active")

	validity := fs.Duration("validity", 365*24*time.Hour, "how long the generated inventory stays acceptable to a verifier")
	inPath := fs.String("in", "", "the current inventory, when regenerating; its version is incremented and its valid_from dates preserved")
	outPath := fs.String("out", "", "path to write the inventory JSON")
	sigPath := fs.String("signature-out", "", "path to write the detached signature")

	if err := fs.Parse(args); err != nil {
		return err
	}

	curve, err := config.ParseCurve(*curveName)
	if err != nil {
		return err
	}
	for name, v := range map[string]string{
		"-module": *modulePath, "-workspace": *workspaceLabel, "-pin-env": *pinEnv,
		"-inventory-workspace": *invWorkspaceLabel, "-inventory-pin-env": *invPINEnv,
		"-inventory-key-label": *invKeyLabel, "-out": *outPath, "-signature-out": *sigPath,
	} {
		if v == "" {
			return fmt.Errorf("%s is required", name)
		}
	}
	if len(keys) == 0 {
		return errors.New("at least one -key is required")
	}
	if err := signingkey.ValidateLabel(*invKeyLabel); err != nil {
		return err
	}
	if *validity <= 0 {
		return fmt.Errorf("-validity must be positive, got %s", *validity)
	}

	// Overwriting -out without reading it would reset the version counter
	// and lose every valid_from, so the previous document has to be named.
	if *inPath == "" {
		if _, err := os.Stat(*outPath); err == nil {
			return fmt.Errorf("%s already exists: pass -in %s to regenerate from it "+
				"(the version counter and the valid_from dates come from there)", *outPath, *outPath)
		} else if !os.IsNotExist(err) {
			return fmt.Errorf("checking output path %s: %w", *outPath, err)
		}
	}

	var previous *inventory.Inventory
	if *inPath != "" {
		data, err := os.ReadFile(*inPath)
		if err != nil {
			return fmt.Errorf("reading the current inventory %s: %w", *inPath, err)
		}
		parsed, err := inventory.Parse(data)
		if err != nil {
			return fmt.Errorf("parsing the current inventory %s: %w", *inPath, err)
		}
		previous = &parsed
	}

	adapter, err := newVendorAdapter(*adapterName, *modulePath)
	if err != nil {
		return err
	}
	defer adapter.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	keyWS, err := findWorkspace(ctx, adapter, *workspaceLabel, *workspaceSerial)
	if err != nil {
		return fmt.Errorf("supply-chain token: %w", err)
	}
	invWS, err := findWorkspace(ctx, adapter, *invWorkspaceLabel, *invWorkspaceSerial)
	if err != nil {
		return fmt.Errorf("inventory signing token: %w", err)
	}
	if keyWS.Serial == invWS.Serial {
		return fmt.Errorf("the supply-chain token and the inventory signing token are one token (serial %q): "+
			"a list of trusted keys signed by a key living on that same token authorises whoever holds it to add their own key",
			keyWS.Serial)
	}

	entries, err := readEntries(ctx, adapter, keyWS, pinResolver(*pinEnv), curve, keys, previous, *invKeyLabel)
	if err != nil {
		return err
	}

	now := time.Now().UTC().Truncate(time.Second)
	version := 1
	if previous != nil {
		version = previous.Version + 1
	}
	// Marshal validates, including the duplicate-public-key check.
	document, err := inventory.Inventory{
		Schema:      inventory.Schema,
		Version:     version,
		GeneratedAt: now,
		ValidUntil:  now.Add(*validity),
		Keys:        entries,
	}.Marshal()
	if err != nil {
		return err
	}

	signature, signerPub, err := signInventory(ctx, adapter, invWS, pinResolver(*invPINEnv), *invKeyLabel, document)
	if err != nil {
		return err
	}
	// Checked before either file is written, against the public half read
	// off the signing token.
	if err := inventory.Verify(document, signature, signerPub); err != nil {
		return fmt.Errorf("the signature this run produced does not verify against %q's public key: %w", *invKeyLabel, err)
	}

	if err := os.WriteFile(*outPath, document, 0644); err != nil {
		return fmt.Errorf("writing %s: %w", *outPath, err)
	}
	if err := os.WriteFile(*sigPath, signature, 0644); err != nil {
		return fmt.Errorf("writing %s: %w", *sigPath, err)
	}

	fmt.Printf("key inventory written:\n  document:  %s (version %d, valid until %s)\n  signature: %s\n  signed by: %s on token %q (serial %s)\n",
		*outPath, version, now.Add(*validity).Format(time.RFC3339), *sigPath, *invKeyLabel, invWS.Label, invWS.Serial)
	for _, e := range entries {
		fmt.Printf("  %-28s %-9s %s\n", e.Label, e.Purpose, e.Status)
	}
	return nil
}

// readEntries turns the -key specs into inventory entries. A live key's
// public half comes off the token. A retired key's comes from the previous
// document, because the key has been destroyed. A key listed as retired
// that is still on the token is an error.
func readEntries(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, resolvePIN func() ([]byte, error), curve pk11.ECCurve, specs keySpecs, previous *inventory.Inventory, invKeyLabel string) (entries []inventory.Entry, err error) {
	prior := map[string]inventory.Entry{}
	if previous != nil {
		for _, e := range previous.Keys {
			prior[e.Label] = e
		}
	}

	if adapter.TokenLoggedIn() {
		return nil, fmt.Errorf("a token is already authenticated before logging into %q; refusing to proceed", ws.Label)
	}
	pin, err := resolvePIN()
	if err != nil {
		return nil, fmt.Errorf("resolving PIN for %q: %w", ws.Label, err)
	}
	if err := adapter.LoginToken(ctx, ws, pin, pk11.RoleUser); err != nil {
		return nil, fmt.Errorf("logging into %q: %w", ws.Label, err)
	}
	defer func() {
		if logoutErr := adapter.LogoutToken(ctx); logoutErr != nil && err == nil {
			err = fmt.Errorf("the keys were read but logging out of %q failed: %w", ws.Label, logoutErr)
		}
	}()

	s, err := adapter.OpenSession(ctx, ws, pk11.DefaultSessionOptions())
	if err != nil {
		return nil, fmt.Errorf("opening a session on %q: %w", ws.Label, err)
	}
	defer func() {
		if closeErr := adapter.CloseSession(ctx, s); closeErr != nil && err == nil {
			err = fmt.Errorf("the keys were read but closing the session failed: %w", closeErr)
		}
	}()

	// The caller compared serials. This confirms the signing key is not
	// also here: a serial is a claim, an object search is a measurement.
	free, err := pk11.LabelIsFree(ctx, adapter, s, pk11.ClassPrivateKey, invKeyLabel)
	if err != nil {
		return nil, fmt.Errorf("checking that %q is absent from the supply-chain token: %w", invKeyLabel, err)
	}
	if !free {
		return nil, fmt.Errorf("the inventory signing key %q is present on the supply-chain token %q: "+
			"whoever holds this token could sign a list naming their own key, so the document would authorise its own forgery",
			invKeyLabel, ws.Label)
	}

	now := time.Now().UTC().Truncate(time.Second)
	for _, spec := range specs {
		if err := signingkey.ValidateLabel(spec.label); err != nil {
			return nil, err
		}
		previousEntry, hadPrevious := prior[spec.label]

		entry := inventory.Entry{
			Label:   spec.label,
			Purpose: spec.purpose,
			Curve:   curveName(curve),
			Status:  spec.status,
		}
		// valid_from is preserved across regenerations.
		entry.ValidFrom = now
		if hadPrevious {
			entry.ValidFrom = previousEntry.ValidFrom
		}

		if spec.status == inventory.StatusRetired {
			if !hadPrevious {
				return nil, fmt.Errorf("%q is listed as retired but is not in the current inventory: "+
					"a retired key's public half comes from the document that listed it while it existed, "+
					"because the key itself has been destroyed on the token", spec.label)
			}
			stillFree, err := pk11.LabelIsFree(ctx, adapter, s, pk11.ClassPrivateKey, spec.label)
			if err != nil {
				return nil, fmt.Errorf("checking whether the retired key %q is gone from the token: %w", spec.label, err)
			}
			if !stillFree {
				return nil, fmt.Errorf("%q is listed as retired but its private key is still on token %q: "+
					"retirement means destroyed on the token, and publishing the claim before "+
					"doing the deed would make this document say something untrue", spec.label, ws.Label)
			}
			entry.PublicKeyPEM = previousEntry.PublicKeyPEM
			retiredAt := previousEntry.RetiredAt
			if retiredAt == nil {
				retiredAt = &now
			}
			entry.RetiredAt = retiredAt
			entries = append(entries, entry)
			continue
		}

		// Verify, not Load, so a key that has become readable never reaches
		// the published list.
		key, err := signingkey.Verify(ctx, adapter, s, spec.label, curve)
		if err != nil {
			return nil, fmt.Errorf("reading %q off token %q: %w", spec.label, ws.Label, err)
		}
		pemBytes, err := key.PEM()
		if err != nil {
			return nil, err
		}
		entry.PublicKeyPEM = string(pemBytes)
		entries = append(entries, entry)
	}

	// Sorted by label, so an unchanged inventory regenerates to identical
	// bytes.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Label < entries[j].Label })
	return entries, nil
}

// signInventory logs into the offline token for one signature and logs out
// afterwards, on every path. It returns the public half so the caller can
// check the signature before publishing it. The signature is ECDSA P-256
// over SHA-256 regardless of -curve: that flag describes the listed keys,
// and the digest algorithm is part of the published verification recipe.
func signInventory(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, resolvePIN func() ([]byte, error), keyLabel string, document []byte) (sig []byte, pub *ecdsa.PublicKey, err error) {
	if adapter.TokenLoggedIn() {
		return nil, nil, fmt.Errorf("a token is already authenticated before logging into %q; refusing to proceed", ws.Label)
	}
	pin, err := resolvePIN()
	if err != nil {
		return nil, nil, fmt.Errorf("resolving PIN for %q: %w", ws.Label, err)
	}
	if err := adapter.LoginToken(ctx, ws, pin, pk11.RoleUser); err != nil {
		return nil, nil, fmt.Errorf("logging into %q: %w", ws.Label, err)
	}
	defer func() {
		if logoutErr := adapter.LogoutToken(ctx); logoutErr != nil && err == nil {
			err = fmt.Errorf("the inventory was signed but logging out of %q failed (the returned signature is valid): %w", ws.Label, logoutErr)
		}
	}()

	// The same crypto.Signer path the CA signs certificates through.
	signer, err := ca.NewSigner(ctx, adapter, ws, pk11.DefaultSessionOptions(), keyLabel, pk11.P256)
	if err != nil {
		return nil, nil, fmt.Errorf("opening the inventory signing key %q on %q: %w", keyLabel, ws.Label, err)
	}
	signerPub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, nil, fmt.Errorf("the inventory signing key %q is not an ECDSA key", keyLabel)
	}
	sig, err = signer.Sign(nil, inventory.Digest(document), crypto.SHA256)
	if err != nil {
		return nil, nil, fmt.Errorf("signing the inventory with %q: %w", keyLabel, err)
	}
	return sig, signerPub, nil
}

// curveName is the inverse of config.ParseCurve.
func curveName(c pk11.ECCurve) string {
	switch c {
	case pk11.P384:
		return "P-384"
	case pk11.P521:
		return "P-521"
	default:
		return "P-256"
	}
}
