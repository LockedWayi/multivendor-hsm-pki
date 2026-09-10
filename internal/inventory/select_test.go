package inventory

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"
)

func testEntry(t *testing.T, label string, p Purpose, s Status, validFrom time.Time, retiredAt *time.Time) Entry {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}
	return Entry{
		Label:        label,
		Purpose:      p,
		Curve:        "P-256",
		PublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})),
		ValidFrom:    validFrom,
		RetiredAt:    retiredAt,
		Status:       s,
	}
}

func labels(entries []Entry) []string {
	var out []string
	for _, e := range entries {
		out = append(out, e.Label)
	}
	return out
}

func TestVerifiableAt(t *testing.T) {
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	past := now.Add(-24 * time.Hour)
	future := now.Add(24 * time.Hour)
	retired := past

	inv := Inventory{
		Schema:      Schema,
		Version:     3,
		GeneratedAt: past,
		ValidUntil:  future,
		Keys: []Entry{
			testEntry(t, "image-signing-key-v1", PurposeImage, StatusVerifyOnly, past, nil),
			testEntry(t, "image-signing-key-v2", PurposeImage, StatusActive, past, nil),
			testEntry(t, "image-signing-key-v3", PurposeImage, StatusActive, future, nil),
			testEntry(t, "image-signing-key-v0", PurposeImage, StatusRetired, past, &retired),
			testEntry(t, "artifact-signing-key-v1", PurposeArtifact, StatusActive, past, nil),
		},
	}
	if err := inv.Validate(); err != nil {
		t.Fatalf("test inventory does not validate: %v", err)
	}

	got, err := inv.VerifiableAt(PurposeImage, now)
	if err != nil {
		t.Fatalf("VerifiableAt: %v", err)
	}
	want := []string{"image-signing-key-v1", "image-signing-key-v2"}
	if len(got) != len(want) {
		t.Fatalf("VerifiableAt = %v, want %v", labels(got), want)
	}
	for i := range want {
		if got[i].Label != want[i] {
			t.Fatalf("VerifiableAt = %v, want %v", labels(got), want)
		}
	}

	active, err := inv.ActiveAt(PurposeImage, now)
	if err != nil {
		t.Fatalf("ActiveAt: %v", err)
	}
	if len(active) != 1 || active[0].Label != "image-signing-key-v2" {
		t.Fatalf("ActiveAt = %v, want [image-signing-key-v2]", labels(active))
	}

	// The not-yet-valid key becomes usable once its valid_from has passed.
	later, err := inv.VerifiableAt(PurposeImage, future.Add(time.Hour))
	if err == nil {
		t.Fatalf("VerifiableAt after valid_until succeeded with %v, want ErrExpired", labels(later))
	}
	if !errors.Is(err, ErrExpired) {
		t.Fatalf("VerifiableAt after valid_until: %v, want ErrExpired", err)
	}
}

func TestVerifiableAt_ExpiredInventoryIsRefusedWhole(t *testing.T) {
	generated := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)
	validUntil := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	now := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	inv := Inventory{
		Schema:      Schema,
		Version:     1,
		GeneratedAt: generated,
		ValidUntil:  validUntil,
		Keys:        []Entry{testEntry(t, "image-signing-key-v1", PurposeImage, StatusActive, generated, nil)},
	}
	for _, fn := range []func() ([]Entry, error){
		func() ([]Entry, error) { return inv.VerifiableAt(PurposeImage, now) },
		func() ([]Entry, error) { return inv.ActiveAt(PurposeImage, now) },
	} {
		got, err := fn()
		if err == nil {
			t.Fatalf("expired inventory selected %v, want ErrExpired", labels(got))
		}
		if !errors.Is(err, ErrExpired) {
			t.Fatalf("error %v is not ErrExpired", err)
		}
		want := "the inventory expired at 2026-01-01T00:00:00Z (now 2026-09-09T12:00:00Z)"
		if err.Error() != "inventory: expired: "+want {
			t.Fatalf("error %q, want %q", err.Error(), "inventory: expired: "+want)
		}
	}
}
