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

// A rendering against the repository's own inventory proves the generator
// runs. It cannot prove the property the phase actually requires -- that the
// policy carries the active *and* the verify-only key at once -- because the
// published inventory has only ever had one image key. That property is what
// makes rotation possible at all, so it is tested against a synthetic
// document rather than left until the first rotation discovers it.
//
// Every synthetic inventory is signed with a fresh test anchor, because the
// generator refuses an unverified document -- that refusal is itself under
// test below, so the happy-path helpers must clear it honestly rather than
// bypass it.

// signInventoryFile signs data with a fresh test anchor and writes the
// detached signature and the anchor's public half where the generator's
// defaults resolve them: <path>.sig, and inventory-signing-key-v1.pub in
// the same directory. inventory.SignWith exists exactly for tests like
// this one (its doc comment says so); production signing goes through the
// offline token and never holds a private key in a Go process.
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
	// valid_until is far-future on purpose: a plausible-looking date would
	// make every test here start failing the day it passed, for a reason
	// unrelated to any change. The expiry refusal has its own test with
	// fixed past dates, which are stable forever.
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

// Two distinct, valid P-256 public keys. They are the repository's own
// published ones, so the test needs no key generation and the rendering can
// be compared against something real.
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
	// This is the rotation window: -v1 still verifies what it signed, -v2
	// signs from now on. A policy holding only one of them makes the day the
	// new key appears the day every running image becomes unverifiable.
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
	// Both keys must be trusted by the same expression, not by two
	// independent rules where one could be dropped without the other
	// failing.
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
			// A retired key has been destroyed on the token. Trusting it
			// would keep accepting images signed before the destruction,
			// which is the state retiring exists to end.
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
	// Emitting it would be fail-closed and useless: every image refused,
	// reading as a broken policy rather than as an empty inventory.
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
	// attestors.<name> is a CEL identifier, so the label loses its hyphens.
	// Two labels reducing to one identifier would silently drop a key the
	// inventory vouches for.
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
	// And it says so where somebody reading the file will see it.
	if !strings.Contains(insecure, "DEVELOPMENT ONLY") {
		t.Error("the concession is not announced in the rendered file")
	}
}

func TestRun_CoversEveryContainerList(t *testing.T) {
	// initContainers and ephemeralContainers are not an afterthought: an
	// unsigned init container runs before the signed one, and an unsigned
	// ephemeral container joins a pod admission already approved.
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

// The three refusals below are the consumer-side half of the inventory's
// trust story, added after an independent audit (2026-09-04) demonstrated a
// tampered inventory rendering straight into an admission policy: the
// generator read the document and never the signature beside it.

func TestRun_RefusesATamperedInventory(t *testing.T) {
	// The audit's exact reproduction: the document is edited after signing,
	// so the committed signature is stale. The edit here is a version bump
	// -- any byte would do, since verification covers the exact bytes and
	// runs before parsing.
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
	// Absence must fail exactly like invalidity: "nothing to check against"
	// and "checked and wrong" both mean the document is unverified.
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
	// The signature on this document is VALID -- the helper signs whatever
	// it writes -- so what this proves is that expiry is checked after, and
	// independently of, the signature: a correctly signed stale list is
	// still a stale list (the freeze attack valid_until exists for).
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

	// An older, correctly signed inventory must not replace it: rolling the
	// rendering back is how a retired key comes back to life.
	older := writeInventoryDoc(t, 3, "2026-09-04T00:00:00Z", "2126-01-01T00:00:00Z", keys)
	_, err := render(t, "-inventory", older, "-out", out)
	if err == nil {
		t.Fatal("replaced a version-7 rendering with a version-3 inventory")
	}
	if !strings.Contains(err.Error(), "refusing the rollback") {
		t.Fatalf("wrong reason: %v", err)
	}

	// Equal version must stay allowed: the dev bring-up re-renders from an
	// unchanged inventory on every run, and a floor that refuses "same"
	// would turn every second deploy into a manual file deletion.
	if _, err := render(t, "-inventory", newer, "-out", out); err != nil {
		t.Fatalf("re-rendering the same version was refused: %v", err)
	}
}

func TestRun_RefusesToReplaceAFileItCannotDate(t *testing.T) {
	// A file at -out with no version header is not a rendering this
	// generator wrote. Overwriting it -- or exempting it from the rollback
	// floor -- would be a decision made by a missing header.
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
	// The rendered file is committed and reviewed; a reader of the diff
	// should see what the document was checked against without re-deriving
	// it.
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
