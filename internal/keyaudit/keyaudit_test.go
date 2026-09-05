package keyaudit_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/keyaudit"
)

// repoRoot walks up from the test's package directory to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("Getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find the module root from the test's working directory")
		}
		dir = parent
	}
}

// TestRepository_HonoursItsOwnKeyInventory is the mechanical half of
// purpose separation and §3.7. Purpose separation is broken by a line in a
// workflow file rather than by a function, so the check has to look at the
// repository — a rule only a careful reader enforces lasts until the first
// hurried afternoon.
//
// It touches no token: the inventory is a document and this reads files.
func TestRepository_HonoursItsOwnKeyInventory(t *testing.T) {
	root := repoRoot(t)
	findings, err := keyaudit.Audit(root)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	for _, f := range findings {
		t.Errorf("%s", f)
	}
}

// TestPublishedInventory_VerifiesAgainstThePublishedAnchor catches the
// drift that matters most: a committed inventory that the committed anchor
// did not sign. It would mean the document was edited after signing, which
// is exactly the thing signing it was supposed to make impossible.
func TestPublishedInventory_VerifiesAgainstThePublishedAnchor(t *testing.T) {
	if err := keyaudit.VerifyPublishedInventory(repoRoot(t)); err != nil {
		t.Fatalf("the committed key inventory does not verify against the committed inventory signing key: %v", err)
	}
}

// TestAudit_CatchesACAKeyInAScript proves the check can fail. A guard that
// has only ever been run against a clean repository has not been shown to be
// a guard — the same discipline as the admission negative test in 4.7 and
// the deliberately outdated image in 4.6.
func TestAudit_CatchesACAKeyInAScript(t *testing.T) {
	root := t.TempDir()
	keys := filepath.Join(root, "docs", "keys")
	if err := os.MkdirAll(keys, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	// Copy the real published artifacts, so the fixture is the genuine
	// document rather than a hand-written one that might not be valid.
	for _, name := range []string{"key-inventory.json", "image-signing-key-v1.pub", "artifact-signing-key-v1.pub"} {
		data, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "keys", name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(keys, name), data, 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}

	script := filepath.Join(root, "sign.sh")
	if err := os.WriteFile(script, []byte(
		"#!/bin/sh\ncosign sign-blob --key 'pkcs11:object=ca-intermediate-key-v1' release.tar.gz\n"), 0755); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings, err := keyaudit.Audit(root)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Audit found %d findings, want exactly 1: %v", len(findings), findings)
	}
	if findings[0].Path != "sign.sh" || findings[0].Line != 2 {
		t.Errorf("finding points at %s:%d, want sign.sh:2", findings[0].Path, findings[0].Line)
	}
}

// TestAudit_CatchesAKeyTheInventoryDoesNotList is the other half: a
// consumer pointed at a key nobody published. Signing with it would produce
// artifacts that every inventory-driven verifier rejects, and the failure
// would surface at a relying party rather than at the build.
func TestAudit_CatchesAKeyTheInventoryDoesNotList(t *testing.T) {
	root := t.TempDir()
	keys := filepath.Join(root, "docs", "keys")
	if err := os.MkdirAll(keys, 0755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	for _, name := range []string{"key-inventory.json", "image-signing-key-v1.pub", "artifact-signing-key-v1.pub"} {
		data, err := os.ReadFile(filepath.Join(repoRoot(t), "docs", "keys", name))
		if err != nil {
			t.Fatalf("reading %s: %v", name, err)
		}
		if err := os.WriteFile(filepath.Join(keys, name), data, 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "policy.yaml"),
		[]byte("keys:\n  - image-signing-key-v9\n"), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	findings, err := keyaudit.Audit(root)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("Audit found %d findings, want exactly 1: %v", len(findings), findings)
	}
}

// TestAudit_RefusesARepositoryWithNoInventory keeps "nothing to check
// against" from looking like "everything checks out".
func TestAudit_RefusesARepositoryWithNoInventory(t *testing.T) {
	if _, err := keyaudit.Audit(t.TempDir()); err == nil {
		t.Fatal("Audit on a repository with no inventory succeeded, want an error")
	}
}
