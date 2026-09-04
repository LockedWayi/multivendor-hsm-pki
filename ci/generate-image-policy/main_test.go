package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A rendering against the repository's own inventory proves the generator
// runs. It cannot prove the property the phase actually requires -- that the
// policy carries the active *and* the verify-only key at once -- because the
// published inventory has only ever had one image key. That property is what
// makes rotation possible at all, so it is tested against a synthetic
// document rather than left until the first rotation discovers it.

func writeInventory(t *testing.T, keys []map[string]any) string {
	t.Helper()
	doc := map[string]any{
		"schema":       "hsm-pki-platform/key-inventory/v1",
		"version":      7,
		"generated_at": "2026-09-04T00:00:00Z",
		"valid_until":  "2027-09-04T00:00:00Z",
		"keys":         keys,
	}
	path := filepath.Join(t.TempDir(), "inventory.json")
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("writing: %v", err)
	}
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
