package inventory_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/inventory"
)

// These tests touch no token — an inventory is a document, and the key that
// signs it in production lives on an HSM but the format does not. So they
// deliberately do not multiply per backend (CLAUDE.md §2.4, and
// docs/test-matrix.md §4).

func pubPEM(t *testing.T, pub *ecdsa.PublicKey) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	return k
}

// validInventory returns a document that passes, so each test can break
// exactly the one thing it is about.
func validInventory(t *testing.T) inventory.Inventory {
	t.Helper()
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	return inventory.Inventory{
		Schema:      inventory.Schema,
		Version:     1,
		GeneratedAt: now,
		ValidUntil:  now.AddDate(1, 0, 0),
		Keys: []inventory.Entry{
			{
				Label:        "artifact-signing-key-v1",
				Purpose:      inventory.PurposeArtifact,
				Curve:        "P-256",
				PublicKeyPEM: pubPEM(t, &newKey(t).PublicKey),
				ValidFrom:    now,
				Status:       inventory.StatusActive,
			},
			{
				Label:        "image-signing-key-v1",
				Purpose:      inventory.PurposeImage,
				Curve:        "P-256",
				PublicKeyPEM: pubPEM(t, &newKey(t).PublicKey),
				ValidFrom:    now,
				Status:       inventory.StatusActive,
			},
		},
	}
}

func TestInventory_RoundTripsThroughParse(t *testing.T) {
	inv := validInventory(t)
	data, err := inv.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	got, err := inventory.Parse(data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got.Keys) != len(inv.Keys) || got.Version != inv.Version {
		t.Fatalf("parsed document differs: %+v", got)
	}
	if !got.GeneratedAt.Equal(inv.GeneratedAt) || !got.ValidUntil.Equal(inv.ValidUntil) {
		t.Error("timestamps did not survive the round trip")
	}
}

// TestInventory_MarshalIsStable pins that regenerating an unchanged
// inventory produces identical bytes. It matters because the document is
// committed and reviewed in diffs: an encoder that reordered keys or
// reformatted numbers would make every rotation an unreadable diff, which
// is most of what checking the file in is supposed to buy.
func TestInventory_MarshalIsStable(t *testing.T) {
	inv := validInventory(t)
	first, err := inv.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	second, err := inv.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if string(first) != string(second) {
		t.Error("two marshals of one inventory produced different bytes")
	}
}

// TestInventory_RejectsTwoLabelsOnOneKey is the assertion this type exists
// for. Every field of this document is individually well-formed; the defect
// is that the image and artifact purposes resolve to one key pair, so a
// compromise of "the image key" also signs releases. Comparing labels sees
// two distinct entries and nothing wrong (CLAUDE.md §3.6, §3.8).
func TestInventory_RejectsTwoLabelsOnOneKey(t *testing.T) {
	inv := validInventory(t)
	inv.Keys[1].PublicKeyPEM = inv.Keys[0].PublicKeyPEM

	err := inv.Validate()
	if !errors.Is(err, inventory.ErrInvalid) {
		t.Fatalf("Validate with one key under two labels = %v, want ErrInvalid", err)
	}
	// Both labels must be named: "duplicate key" without saying which two
	// entries collide leaves an operator to find them by hand.
	for _, label := range []string{inv.Keys[0].Label, inv.Keys[1].Label} {
		if !strings.Contains(err.Error(), label) {
			t.Errorf("error does not name %q: %v", label, err)
		}
	}
}

func TestInventory_ValidateRejects(t *testing.T) {
	retired := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	early := time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC)

	cases := map[string]func(inv *inventory.Inventory){
		"a schema this build does not implement": func(inv *inventory.Inventory) {
			inv.Schema = "hsm-pki-platform/key-inventory/v99"
		},
		"a version that cannot be compared against a previous one": func(inv *inventory.Inventory) {
			inv.Version = 0
		},
		// Without an expiry an attacker who withholds updates replays this
		// document forever, and a retired key never dies.
		"no expiry": func(inv *inventory.Inventory) {
			inv.ValidUntil = time.Time{}
		},
		"an expiry before the generation time": func(inv *inventory.Inventory) {
			inv.ValidUntil = inv.GeneratedAt.Add(-time.Hour)
		},
		"no keys at all": func(inv *inventory.Inventory) {
			inv.Keys = nil
		},
		"a label repeated": func(inv *inventory.Inventory) {
			inv.Keys[1].Label = inv.Keys[0].Label
		},
		"a purpose no verifier can enforce": func(inv *inventory.Inventory) {
			inv.Keys[0].Purpose = "everything"
		},
		"a status outside the lifecycle": func(inv *inventory.Inventory) {
			inv.Keys[0].Status = "probably-fine"
		},
		"a retired key with no retirement date": func(inv *inventory.Inventory) {
			inv.Keys[0].Status = inventory.StatusRetired
		},
		"a live key carrying a retirement date": func(inv *inventory.Inventory) {
			inv.Keys[0].RetiredAt = &retired
		},
		"a key retired before it was valid": func(inv *inventory.Inventory) {
			inv.Keys[0].Status = inventory.StatusRetired
			inv.Keys[0].RetiredAt = &early
		},
		"no curve": func(inv *inventory.Inventory) {
			inv.Keys[0].Curve = ""
		},
		"no valid_from": func(inv *inventory.Inventory) {
			inv.Keys[0].ValidFrom = time.Time{}
		},
		"a public key that is not a PEM block": func(inv *inventory.Inventory) {
			inv.Keys[0].PublicKeyPEM = "not a pem block"
		},
		"a PEM block holding a private key": func(inv *inventory.Inventory) {
			inv.Keys[0].PublicKeyPEM = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
		},
	}

	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			inv := validInventory(t)
			breakIt(&inv)
			if err := inv.Validate(); !errors.Is(err, inventory.ErrInvalid) {
				t.Fatalf("Validate accepted %s: %v", name, err)
			}
			// Marshal must refuse too, or an invalid document reaches disk
			// and gets signed, which is the failure that matters.
			if _, err := inv.Marshal(); err == nil {
				t.Error("Marshal produced bytes for an invalid inventory")
			}
		})
	}
}

// TestParse_RejectsAnUnknownField fails closed on a document this build
// does not fully understand: an unrecognised field may be saying something
// about a key that changes whether it should be trusted (CLAUDE.md §3.4).
func TestParse_RejectsAnUnknownField(t *testing.T) {
	inv := validInventory(t)
	data, err := inv.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var generic map[string]any
	if err := json.Unmarshal(data, &generic); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	generic["revocations"] = []string{"image-signing-key-v1"}
	tampered, err := json.Marshal(generic)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	if _, err := inventory.Parse(tampered); !errors.Is(err, inventory.ErrInvalid) {
		t.Fatalf("Parse accepted a document with an unknown field: %v", err)
	}
}

func TestInventory_ActiveAndVerifiableSeparateTheLifecycle(t *testing.T) {
	now := time.Date(2026, 9, 4, 12, 0, 0, 0, time.UTC)
	retired := now.Add(24 * time.Hour)
	inv := validInventory(t)
	inv.Keys[1].Status = inventory.StatusVerifyOnly
	inv.Keys = append(inv.Keys, inventory.Entry{
		Label:        "image-signing-key-v0",
		Purpose:      inventory.PurposeImage,
		Curve:        "P-256",
		PublicKeyPEM: pubPEM(t, &newKey(t).PublicKey),
		ValidFrom:    now,
		RetiredAt:    &retired,
		Status:       inventory.StatusRetired,
	})
	if err := inv.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// A verify-only key signs nothing new — that is the whole content of
	// the middle lifecycle state.
	if got := inv.Active(inventory.PurposeImage); len(got) != 0 {
		t.Errorf("Active(image) = %d entries, want 0 (v1 is verify-only, v0 retired)", len(got))
	}
	// ...but signatures it already made still verify, which is what makes
	// rotation something other than a flag day.
	if got := inv.Verifiable(inventory.PurposeImage); len(got) != 1 || got[0].Label != "image-signing-key-v1" {
		t.Errorf("Verifiable(image) = %+v, want just image-signing-key-v1", got)
	}
	// The retired key verifies nothing, and the purposes do not leak into
	// each other.
	if got := inv.Active(inventory.PurposeArtifact); len(got) != 1 {
		t.Errorf("Active(artifact) = %d entries, want 1", len(got))
	}
}

func TestVerify_AcceptsAGoodSignatureAndRejectsTampering(t *testing.T) {
	signer := newKey(t)
	inv := validInventory(t)
	document, err := inv.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	sig, err := inventory.SignWith(document, signer)
	if err != nil {
		t.Fatalf("SignWith: %v", err)
	}

	if err := inventory.Verify(document, sig, &signer.PublicKey); err != nil {
		t.Fatalf("Verify on a good signature: %v", err)
	}

	// One byte. The point of signing the document rather than a canonical
	// re-encoding is that any change at all is a different document.
	tampered := append([]byte(nil), document...)
	tampered[len(tampered)/2] ^= 0x01
	if err := inventory.Verify(tampered, sig, &signer.PublicKey); err == nil {
		t.Error("Verify accepted a document with one byte changed")
	}

	// A different key must not verify, or the inventory authorises whoever
	// holds any key rather than the one it names.
	if err := inventory.Verify(document, sig, &newKey(t).PublicKey); err == nil {
		t.Error("Verify accepted a signature from an unrelated key")
	}
}

// TestVerify_AgreesWithOpenSSL is the check that matters most here
// (CLAUDE.md §3.10). Everything above proves this package agrees with
// itself, which it would do just as convincingly if the digest, the
// signature encoding, or the bytes being signed were all wrong together.
// The published contract is that anyone holding the inventory, the
// signature and the public key can verify it with ordinary tools, so that
// claim is tested against an implementation that has never seen this
// repository.
func TestVerify_AgreesWithOpenSSL(t *testing.T) {
	openssl, err := exec.LookPath("openssl")
	if err != nil {
		t.Skip("openssl not installed; the Go-side signature checks above still ran")
	}

	dir := t.TempDir()
	signer := newKey(t)
	inv := validInventory(t)
	document, err := inv.Marshal()
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	sig, err := inventory.SignWith(document, signer)
	if err != nil {
		t.Fatalf("SignWith: %v", err)
	}

	docPath := filepath.Join(dir, "key-inventory.json")
	sigPath := filepath.Join(dir, "key-inventory.json.sig")
	pubPath := filepath.Join(dir, "inventory-signing-key.pub")
	if err := os.WriteFile(docPath, document, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(sigPath, sig, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if err := os.WriteFile(pubPath, []byte(pubPEM(t, &signer.PublicKey)), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	// Exactly the command the package comment publishes as the recipe. If
	// this ever needs a flag the documentation does not mention, the
	// documentation is wrong.
	out, err := exec.Command(openssl, "dgst", "-sha256", "-verify", pubPath,
		"-signature", sigPath, docPath).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl rejected a signature this package produced: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "Verified OK") {
		t.Fatalf("openssl output = %q, want \"Verified OK\"", out)
	}

	// And it must reject a tampered document, or the check above only
	// proves openssl says yes to everything.
	tampered := append([]byte(nil), document...)
	tampered[len(tampered)/2] ^= 0x01
	if err := os.WriteFile(docPath, tampered, 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if out, err := exec.Command(openssl, "dgst", "-sha256", "-verify", pubPath,
		"-signature", sigPath, docPath).CombinedOutput(); err == nil {
		t.Fatalf("openssl accepted a tampered document: %s", out)
	}
}
