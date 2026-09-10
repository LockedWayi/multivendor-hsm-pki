package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/inventory"
)

// The published inventory has only ever had one image key, so the
// property that matters, a policy carrying the active and the verify-only
// key at once, is tested against a synthetic document. Every synthetic
// inventory is signed with a fresh test anchor, because the generator
// refuses an unverified document.

// signInventoryFile signs data with a fresh test anchor and writes the
// signature and the anchor where the generator's defaults resolve them.
func signInventoryFile(t *testing.T, path string, data []byte) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a test anchor: %v", err)
	}
	sig, err := inventory.SignWith(data, priv)
	if err != nil {
		t.Fatalf("signing the test inventory: %v", err)
	}
	if err := os.WriteFile(path+".sig", sig, 0o600); err != nil {
		t.Fatalf("writing the signature: %v", err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatalf("marshalling the anchor: %v", err)
	}
	anchorPEM := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	anchorPath := filepath.Join(filepath.Dir(path), "inventory-signing-key-v1.pub")
	if err := os.WriteFile(anchorPath, anchorPEM, 0o600); err != nil {
		t.Fatalf("writing the anchor: %v", err)
	}
}

func writeInventory(t *testing.T, keys []map[string]any) string {
	t.Helper()
	// valid_until is far in the future so these tests do not start failing
	// on a date. The expiry refusal has its own test with fixed past dates.
	return writeInventoryDoc(t, 7, "2026-09-04T00:00:00Z", "2126-01-01T00:00:00Z", keys)
}

func writeInventoryDoc(t *testing.T, version int, generatedAt, validUntil string, keys []map[string]any) string {
	t.Helper()
	doc := map[string]any{
		"schema":       "hsm-pki-platform/key-inventory/v1",
		"version":      version,
		"generated_at": generatedAt,
		"valid_until":  validUntil,
		"keys":         keys,
	}
	path := filepath.Join(t.TempDir(), "inventory.json")
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	signInventoryFile(t, path, data)
	return path
}

func imageKey(label, status string, pem string) map[string]any {
	e := map[string]any{
		"label":      label,
		"purpose":    "image",
		"public_key": pem,
		"curve":      "P-256",
		"valid_from": "2026-09-04T00:00:00Z",
		"status":     status,
	}
	if status == "retired" {
		e["retired_at"] = "2026-09-04T00:00:00Z"
	}
	return e
}

// publishedPEM returns one of the repository's own published keys.
func publishedPEM(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "keys", name))
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(data)
}

func render(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out strings.Builder
	err := run(args, &out)
	return out.String(), err
}

func TestRun_CarriesActiveAndVerifyOnlyTogether(t *testing.T) {
	// The rotation window: v1 still verifies, v2 signs.
	inv := writeInventory(t, []map[string]any{
		imageKey("image-signing-key-v1", "verify-only", publishedPEM(t, "image-signing-key-v1.pub")),
		imageKey("image-signing-key-v2", "active", publishedPEM(t, "artifact-signing-key-v1.pub")),
	})
	out, err := render(t, "-inventory", inv)
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	for _, want := range []string{
		"image-signing-key-v1", "image-signing-key-v2",
		"attestors.imagesigningkeyv1", "attestors.imagesigningkeyv2",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("the rendered policy does not carry %q", want)
		}
	}
	// Both keys in one expression.
	if !strings.Contains(out, "attestors.imagesigningkeyv1, attestors.imagesigningkeyv2") {
		t.Errorf("the two keys are not offered to one verification:\n%s", out)
	}
}

func TestRun_LeavesOutWhatMustNotBeTrusted(t *testing.T) {
	cases := []struct {
		name   string
		keys   []map[string]any
		absent string
	}{
		{
			name: "a retired key",
			keys: []map[string]any{
				imageKey("image-signing-key-v1", "retired", publishedPEM(t, "image-signing-key-v1.pub")),
				imageKey("image-signing-key-v2", "active", publishedPEM(t, "artifact-signing-key-v1.pub")),
			},
			absent: "attestors.imagesigningkeyv1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := render(t, "-inventory", writeInventory(t, tc.keys))
			if err != nil {
				t.Fatalf("rendering: %v", err)
			}
			if strings.Contains(out, tc.absent) {
				t.Errorf("the rendered policy trusts %q, which it must not:\n%s", tc.absent, out)
			}
		})
	}
}

func TestRun_RefusesToRenderAPolicyThatTrustsNothing(t *testing.T) {
	// A policy with no attestors would read as a broken policy.
	inv := writeInventory(t, []map[string]any{
		imageKey("image-signing-key-v1", "retired", publishedPEM(t, "image-signing-key-v1.pub")),
	})
	if _, err := render(t, "-inventory", inv); err == nil {
		t.Fatal("rendered a policy with no trusted key")
	} else if !strings.Contains(err.Error(), "nothing for the cluster to trust") {
		t.Fatalf("wrong reason: %v", err)
	}
}

func TestRun_RefusesLabelsThatCollideAsCELIdentifiers(t *testing.T) {
	// Two labels reducing to one CEL identifier would drop a key.
	inv := writeInventory(t, []map[string]any{
		imageKey("image-signing-key-v1", "active", publishedPEM(t, "image-signing-key-v1.pub")),
		imageKey("image-signing-keyv1", "active", publishedPEM(t, "artifact-signing-key-v1.pub")),
	})
	_, err := render(t, "-inventory", inv)
	if err == nil {
		t.Fatal("rendered a policy in which one key silently replaced another")
	}
	if !strings.Contains(err.Error(), "CEL identifier") {
		t.Fatalf("wrong reason: %v", err)
	}
}

func TestRun_InsecureRegistryIsOffUnlessAskedFor(t *testing.T) {
	inv := writeInventory(t, []map[string]any{
		imageKey("image-signing-key-v1", "active", publishedPEM(t, "image-signing-key-v1.pub")),
	})
	secure, err := render(t, "-inventory", inv)
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if strings.Contains(secure, "allowInsecureRegistry") {
		t.Error("the default rendering allows plaintext registry access")
	}
	insecure, err := render(t, "-inventory", inv, "-allow-insecure-registry")
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if !strings.Contains(insecure, "allowInsecureRegistry: true") {
		t.Error("-allow-insecure-registry did not reach the policy")
	}
	// And the file says so.
	if !strings.Contains(insecure, "DEVELOPMENT ONLY") {
		t.Error("the concession is not announced in the rendered file")
	}
}

func TestRun_CoversEveryContainerList(t *testing.T) {
	// An unsigned init container runs before the signed one; an unsigned
	// ephemeral container joins an admitted pod.
	inv := writeInventory(t, []map[string]any{
		imageKey("image-signing-key-v1", "active", publishedPEM(t, "image-signing-key-v1.pub")),
	})
	out, err := render(t, "-inventory", inv)
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	for _, list := range []string{"images.containers", "images.initContainers", "images.ephemeralContainers"} {
		if !strings.Contains(out, list) {
			t.Errorf("no validation over %s", list)
		}
	}
	if !strings.Contains(out, "pods/ephemeralcontainers") {
		t.Error("the policy does not match the ephemeralcontainers subresource")
	}
}

// The three refusals below were added after a tampered inventory rendered
// straight into an admission policy: the generator read the document and
// never the signature beside it.

func TestRun_RefusesATamperedInventory(t *testing.T) {
	// The document is edited after signing. Verification covers the exact
	// bytes and runs before parsing.
	inv := writeInventory(t, []map[string]any{
		imageKey("image-signing-key-v1", "active", publishedPEM(t, "image-signing-key-v1.pub")),
	})
	data, err := os.ReadFile(inv)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	tampered := strings.Replace(string(data), `"version": 7`, `"version": 8`, 1)
	if tampered == string(data) {
		t.Fatal("the tamper did not change the document; the test is broken")
	}
	if err := os.WriteFile(inv, []byte(tampered), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	_, err = render(t, "-inventory", inv)
	if err == nil {
		t.Fatal("rendered a policy from a document whose signature no longer verifies")
	}
	if !strings.Contains(err.Error(), "signature does not verify") {
		t.Fatalf("wrong reason: %v", err)
	}
}

func TestRun_RefusesAMissingSignature(t *testing.T) {
	// A missing signature fails like an invalid one.
	inv := writeInventory(t, []map[string]any{
		imageKey("image-signing-key-v1", "active", publishedPEM(t, "image-signing-key-v1.pub")),
	})
	if err := os.Remove(inv + ".sig"); err != nil {
		t.Fatalf("removing the signature: %v", err)
	}
	_, err := render(t, "-inventory", inv)
	if err == nil {
		t.Fatal("rendered a policy from a document with no signature at all")
	}
	if !strings.Contains(err.Error(), "reading the inventory's signature") {
		t.Fatalf("wrong reason: %v", err)
	}
}

func TestRun_RefusesAnExpiredInventory(t *testing.T) {
	// The signature is valid, so this shows expiry is checked after, and
	// independently of, the signature.
	inv := writeInventoryDoc(t, 7, "2025-01-01T00:00:00Z", "2026-01-01T00:00:00Z", []map[string]any{
		imageKey("image-signing-key-v1", "active", publishedPEM(t, "image-signing-key-v1.pub")),
	})
	_, err := render(t, "-inventory", inv)
	if err == nil {
		t.Fatal("rendered a policy from an expired inventory")
	}
	if !strings.Contains(err.Error(), "expired at") {
		t.Fatalf("wrong reason: %v", err)
	}
}

func TestRun_RefusesAVersionRollback(t *testing.T) {
	keys := []map[string]any{
		imageKey("image-signing-key-v1", "active", publishedPEM(t, "image-signing-key-v1.pub")),
	}
	out := filepath.Join(t.TempDir(), "image-signature.yaml")

	newer := writeInventoryDoc(t, 7, "2026-09-04T00:00:00Z", "2126-01-01T00:00:00Z", keys)
	if _, err := render(t, "-inventory", newer, "-out", out); err != nil {
		t.Fatalf("rendering version 7: %v", err)
	}

	// An older, correctly signed inventory must not replace it.
	older := writeInventoryDoc(t, 3, "2026-09-04T00:00:00Z", "2126-01-01T00:00:00Z", keys)
	_, err := render(t, "-inventory", older, "-out", out)
	if err == nil {
		t.Fatal("replaced a version-7 rendering with a version-3 inventory")
	}
	if !strings.Contains(err.Error(), "refusing the rollback") {
		t.Fatalf("wrong reason: %v", err)
	}

	// An equal version stays allowed: the dev bring-up re-renders from an
	// unchanged inventory on every run.
	if _, err := render(t, "-inventory", newer, "-out", out); err != nil {
		t.Fatalf("re-rendering the same version was refused: %v", err)
	}
}

func TestRun_RefusesToReplaceAFileItCannotDate(t *testing.T) {
	// A file at -out with no version header was not written by this
	// generator.
	out := filepath.Join(t.TempDir(), "image-signature.yaml")
	if err := os.WriteFile(out, []byte("apiVersion: v1 # hand-written\n"), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
	inv := writeInventory(t, []map[string]any{
		imageKey("image-signing-key-v1", "active", publishedPEM(t, "image-signing-key-v1.pub")),
	})
	_, err := render(t, "-inventory", inv, "-out", out)
	if err == nil {
		t.Fatal("overwrote a file with no version header")
	}
	if !strings.Contains(err.Error(), "no \"Rendered from") {
		t.Fatalf("wrong reason: %v", err)
	}
}

func TestRun_RecordsTheVerificationInTheRenderedHeader(t *testing.T) {
	// The rendered header names what the document was checked against.
	inv := writeInventory(t, []map[string]any{
		imageKey("image-signing-key-v1", "active", publishedPEM(t, "image-signing-key-v1.pub")),
	})
	out, err := render(t, "-inventory", inv)
	if err != nil {
		t.Fatalf("rendering: %v", err)
	}
	if !strings.Contains(out, "signature was verified against") ||
		!strings.Contains(out, "inventory-signing-key-v1.pub") {
		t.Error("the rendered header does not say what the inventory was verified against")
	}
}
