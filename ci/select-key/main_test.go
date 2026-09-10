package main

import (
	"bytes"
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
	"time"
)

func testPEM(t *testing.T) string {
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

func key(t *testing.T, label, purpose, status, validFrom string, retiredAt any) map[string]any {
	t.Helper()
	return map[string]any{
		"label": label, "purpose": purpose, "curve": "P-256",
		"public_key": testPEM(t), "valid_from": validFrom,
		"retired_at": retiredAt, "status": status,
	}
}

func writeInventory(t *testing.T, validUntil string, keys []map[string]any) string {
	t.Helper()
	doc := map[string]any{
		"schema":       "hsm-pki-platform/key-inventory/v1",
		"version":      1,
		"generated_at": "2026-01-01T00:00:00Z",
		"valid_until":  validUntil,
		"keys":         keys,
	}
	data, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		t.Fatalf("MarshalIndent: %v", err)
	}
	path := filepath.Join(t.TempDir(), "key-inventory.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestRun_SelectsVerifiableKeysAtDate(t *testing.T) {
	inv := writeInventory(t, "2027-01-01T00:00:00Z", []map[string]any{
		key(t, "image-signing-key-v1", "image", "verify-only", "2026-01-01T00:00:00Z", nil),
		key(t, "image-signing-key-v2", "image", "active", "2026-06-01T00:00:00Z", nil),
		key(t, "artifact-signing-key-v1", "artifact", "active", "2026-01-01T00:00:00Z", nil),
	})
	outDir := filepath.Join(t.TempDir(), "keys")
	var out bytes.Buffer
	err := run([]string{"-inventory", inv, "-purpose", "image", "-at", "2026-09-09T00:00:00Z", "-out-dir", outDir}, &out, time.Now())
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2:\n%s", len(lines), out.String())
	}
	if !strings.HasPrefix(lines[0], "image-signing-key-v1\tverify-only\t") ||
		!strings.HasPrefix(lines[1], "image-signing-key-v2\tactive\t") {
		t.Fatalf("unexpected output:\n%s", out.String())
	}
	for _, label := range []string{"image-signing-key-v1", "image-signing-key-v2"} {
		data, err := os.ReadFile(filepath.Join(outDir, label+".pub"))
		if err != nil {
			t.Fatalf("the PEM for %s was not written: %v", label, err)
		}
		if !strings.Contains(string(data), "BEGIN PUBLIC KEY") {
			t.Fatalf("%s.pub is not a PEM public key", label)
		}
	}
	if _, err := os.Stat(filepath.Join(outDir, "artifact-signing-key-v1.pub")); err == nil {
		t.Fatal("a key of another purpose was written")
	}
}

func TestRun_ActiveOnlyExcludesVerifyOnly(t *testing.T) {
	inv := writeInventory(t, "2027-01-01T00:00:00Z", []map[string]any{
		key(t, "image-signing-key-v1", "image", "verify-only", "2026-01-01T00:00:00Z", nil),
		key(t, "image-signing-key-v2", "image", "active", "2026-01-01T00:00:00Z", nil),
	})
	var out bytes.Buffer
	if err := run([]string{"-inventory", inv, "-purpose", "image", "-at", "2026-09-09T00:00:00Z", "-active-only"}, &out, time.Now()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if got := strings.TrimSpace(out.String()); got != "image-signing-key-v2\tactive\t-" {
		t.Fatalf("got %q", got)
	}
}

func TestRun_RefusesAnExpiredInventory(t *testing.T) {
	inv := writeInventory(t, "2026-06-01T00:00:00Z", []map[string]any{
		key(t, "image-signing-key-v1", "image", "active", "2026-01-01T00:00:00Z", nil),
	})
	var out bytes.Buffer
	err := run([]string{"-inventory", inv, "-purpose", "image", "-at", "2026-09-09T12:00:00Z"}, &out, time.Now())
	if err == nil {
		t.Fatalf("an expired inventory was accepted:\n%s", out.String())
	}
	want := "the inventory expired at 2026-06-01T00:00:00Z (now 2026-09-09T12:00:00Z)"
	if !strings.Contains(err.Error(), want) {
		t.Fatalf("error %q does not carry %q", err.Error(), want)
	}
	if out.Len() != 0 {
		t.Fatalf("keys were printed from an expired inventory:\n%s", out.String())
	}
}

func TestRun_ExcludesANotYetValidKey(t *testing.T) {
	inv := writeInventory(t, "2027-01-01T00:00:00Z", []map[string]any{
		key(t, "image-signing-key-v1", "image", "active", "2026-12-01T00:00:00Z", nil),
	})
	var out bytes.Buffer
	err := run([]string{"-inventory", inv, "-purpose", "image", "-at", "2026-09-09T00:00:00Z"}, &out, time.Now())
	if err == nil {
		t.Fatalf("a key whose valid_from is in the future was selected:\n%s", out.String())
	}
	if !strings.Contains(err.Error(), "no usable image key at 2026-09-09T00:00:00Z") {
		t.Fatalf("error %q does not say no key is usable", err.Error())
	}
	out.Reset()
	if err := run([]string{"-inventory", inv, "-purpose", "image", "-at", "2026-12-02T00:00:00Z"}, &out, time.Now()); err != nil {
		t.Fatalf("the same key after its valid_from: %v", err)
	}
}

func TestRun_ExcludesARetiredKey(t *testing.T) {
	inv := writeInventory(t, "2027-01-01T00:00:00Z", []map[string]any{
		key(t, "image-signing-key-v1", "image", "retired", "2026-01-01T00:00:00Z", "2026-03-01T00:00:00Z"),
		key(t, "image-signing-key-v2", "image", "active", "2026-03-01T00:00:00Z", nil),
	})
	var out bytes.Buffer
	if err := run([]string{"-inventory", inv, "-purpose", "image", "-at", "2026-09-09T00:00:00Z"}, &out, time.Now()); err != nil {
		t.Fatalf("run: %v", err)
	}
	if strings.Contains(out.String(), "image-signing-key-v1") {
		t.Fatalf("a retired key was selected:\n%s", out.String())
	}
	if !strings.Contains(out.String(), "image-signing-key-v2\tactive") {
		t.Fatalf("the active key was not selected:\n%s", out.String())
	}
}

func TestRun_RefusesAnUnknownPurposeAndABadDate(t *testing.T) {
	inv := writeInventory(t, "2027-01-01T00:00:00Z", []map[string]any{
		key(t, "image-signing-key-v1", "image", "active", "2026-01-01T00:00:00Z", nil),
	})
	var out bytes.Buffer
	if err := run([]string{"-inventory", inv, "-purpose", "audit", "-at", "2026-09-09T00:00:00Z"}, &out, time.Now()); err == nil {
		t.Fatal("an unknown purpose selected a key")
	}
	if err := run([]string{"-inventory", inv, "-purpose", "image", "-at", "yesterday"}, &out, time.Now()); err == nil {
		t.Fatal("a malformed -at was accepted")
	}
	if err := run([]string{"-inventory", inv}, &out, time.Now()); err == nil {
		t.Fatal("a missing -purpose was accepted")
	}
}
