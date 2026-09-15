package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/inventory"
)

// listing writes an inventory that lists label with status and pubPEM,
// into its own directory, and returns the path. Unsigned: the command
// reads the document the way generate-inventory -in does, without
// checking the signature.
func listing(t *testing.T, label string, status inventory.Status, pubPEM string) string {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	var retiredAt *time.Time
	if status == inventory.StatusRetired {
		retiredAt = &now
	}
	doc, err := inventory.Inventory{
		Schema: inventory.Schema, Version: 2, GeneratedAt: now, ValidUntil: now.Add(24 * time.Hour),
		Keys: []inventory.Entry{{
			Label: label, Purpose: inventory.PurposeImage, Curve: "P-256",
			PublicKeyPEM: pubPEM, ValidFrom: now.Add(-time.Hour), RetiredAt: retiredAt, Status: status,
		}},
	}.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	path := filepath.Join(t.TempDir(), "key-inventory.json")
	if err := os.WriteFile(path, doc, 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

// otherPEM is a public key that is on no token.
func otherPEM(t *testing.T) string {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// retireArgs builds a complete flag set and releases the harness's
// adapter, because the command opens the module itself.
func retireArgs(t *testing.T, b *hsmtest.Backend, keyLabel, inventoryPath string) []string {
	t.Helper()
	const pinEnv = "KEYTOOL_TEST_SIGNING_PIN"
	t.Setenv(pinEnv, b.PrimaryPIN)
	b.Release()
	return []string{
		"-adapter", b.AdapterName,
		"-module", b.ModulePath,
		"-workspace", b.Primary.Label,
		"-pin-env", pinEnv,
		"-key-label", keyLabel,
		"-inventory", inventoryPath,
	}
}

// provisionForRetirement puts a key on the token through the provision
// command and returns its exported public key.
func provisionForRetirement(t *testing.T, b *hsmtest.Backend, label string) string {
	t.Helper()
	dir := t.TempDir()
	if err := runProvisionSigningKeyCmd(provisionArgs(t, b, dir, label)); err != nil {
		t.Fatalf("provisioning %s: %v", label, err)
	}
	pubPEM, err := os.ReadFile(filepath.Join(dir, "signing.pub"))
	if err != nil {
		t.Fatalf("reading the exported public key: %v", err)
	}
	return string(pubPEM)
}

// TestRunRetireSigningKeyCmd_DestroysAVerifyOnlyKeyOnce runs the command
// as an operator does, then runs it again to show the key is gone.
func TestRunRetireSigningKeyCmd_DestroysAVerifyOnlyKeyOnce(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		label := b.Label("image-signing-key-v1")
		pubPEM := provisionForRetirement(t, b, label)
		args := retireArgs(t, b, label, listing(t, label, inventory.StatusVerifyOnly, pubPEM))

		if err := runRetireSigningKeyCmd(args); err != nil {
			t.Fatalf("runRetireSigningKeyCmd: %v", err)
		}
		err := runRetireSigningKeyCmd(args)
		if err == nil || !strings.Contains(err.Error(), "no key object found") {
			t.Fatalf("second run = %v, want the key to be gone from the token", err)
		}
	})
}

// TestRunRetireSigningKeyCmd_RefusesAKeyThatIsNotTheOneListed: the label
// is addressing. A token whose object under that label is not the key
// the inventory lists is refused, and the refusal destroys nothing, shown
// by retiring with the right listing afterwards.
func TestRunRetireSigningKeyCmd_RefusesAKeyThatIsNotTheOneListed(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		label := b.Label("image-signing-key-v1")
		pubPEM := provisionForRetirement(t, b, label)

		wrong := retireArgs(t, b, label, listing(t, label, inventory.StatusVerifyOnly, otherPEM(t)))
		err := runRetireSigningKeyCmd(wrong)
		if err == nil || !strings.Contains(err.Error(), "is not the key the inventory lists") {
			t.Fatalf("retire against a listing of another key = %v, want a refusal naming the mismatch", err)
		}

		right := retireArgs(t, b, label, listing(t, label, inventory.StatusVerifyOnly, pubPEM))
		if err := runRetireSigningKeyCmd(right); err != nil {
			t.Fatalf("the key should still be on the token after the refusal, but retiring it failed: %v", err)
		}
	})
}

// TestRunRetireSigningKeyCmd_RefusesBeforeTouchingTheToken pins the
// ordering: every refusal below is reached with a module path that does
// not exist and no PIN set, so an error that mentions either would mean
// the token was reached first. No token.
func TestRunRetireSigningKeyCmd_RefusesBeforeTouchingTheToken(t *testing.T) {
	const label = "image-signing-key-v1"
	pubPEM := otherPEM(t)
	args := func(keyLabel, inventoryPath string) []string {
		return []string{
			"-module", "/nonexistent/module.so",
			"-workspace", "some-token",
			"-pin-env", "KEYTOOL_TEST_PIN_THAT_IS_NOT_SET",
			"-key-label", keyLabel,
			"-inventory", inventoryPath,
		}
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"a key the inventory lists as active", args(label, listing(t, label, inventory.StatusActive, pubPEM)), "rotated, not retired"},
		{"a key the inventory already lists as retired", args(label, listing(t, label, inventory.StatusRetired, pubPEM)), "already listed as retired"},
		{"a key the inventory does not list", args("image-signing-key-v9", listing(t, label, inventory.StatusVerifyOnly, pubPEM)), "is not listed"},
		{"an unversioned label", args("image-signing-key", listing(t, label, inventory.StatusVerifyOnly, pubPEM)), "versioned label"},
		{"an inventory that is not there", args(label, "/nonexistent/key-inventory.json"), "reading the inventory"},
		{"no inventory given", args(label, "")[:10], "-inventory is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := runRetireSigningKeyCmd(tc.args)
			if err == nil {
				t.Fatal("the command succeeded")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error = %v, want it to say %q", err, tc.want)
			}
			if strings.Contains(err.Error(), "module") || strings.Contains(err.Error(), "PIN") {
				t.Fatalf("refused for the wrong reason, after reaching for the token: %v", err)
			}
		})
	}
}

// TestRun_RoutesTheRetireSubcommand: a subcommand missing from run's
// switch cannot be invoked. No token.
func TestRun_RoutesTheRetireSubcommand(t *testing.T) {
	err := run([]string{"retire-signing-key"})
	if err == nil {
		t.Fatal("run(retire-signing-key) with no flags succeeded, want an error")
	}
	if strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("retire-signing-key is not routed by run: %v", err)
	}
}
