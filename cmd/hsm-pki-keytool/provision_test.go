package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LockedWayi/hsm-pki-platform/internal/hsmtest"
	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
	"github.com/LockedWayi/hsm-pki-platform/internal/signingkey"
)

// provisionArgs builds a complete, valid flag set so each test can change
// exactly the one thing it is about.
//
// It releases the harness's adapter for the same reason ceremonyArgs does:
// the command opens the module itself, and ProtectToolkit refuses a second
// C_Initialize in one process. Anything a test needs to put on the token
// must therefore happen before this is called.
func provisionArgs(t *testing.T, b *hsmtest.Backend, dir, keyLabel string) []string {
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
		"-public-key-out", filepath.Join(dir, "signing.pub"),
	}
}

// TestRunProvisionSigningKeyCmd_WritesAPublicKeyAVerifierCanUse runs the
// command the way an operator does and then reads its output the way a
// verifier will — through the standard library's generic PKIX path, not
// through anything that knows how this repository wrote it (CLAUDE.md
// §3.10).
func TestRunProvisionSigningKeyCmd_WritesAPublicKeyAVerifierCanUse(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		dir := t.TempDir()
		args := provisionArgs(t, b, dir, b.Label("image-signing-key-v1"))

		if err := runProvisionSigningKeyCmd(args); err != nil {
			t.Fatalf("runProvisionSigningKeyCmd: %v", err)
		}

		out, err := os.ReadFile(filepath.Join(dir, "signing.pub"))
		if err != nil {
			t.Fatalf("reading the exported public key: %v", err)
		}
		block, rest := pem.Decode(out)
		if block == nil || block.Type != "PUBLIC KEY" || len(rest) != 0 {
			t.Fatalf("output is not a single PUBLIC KEY block: %q", out)
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			t.Fatalf("ParsePKIXPublicKey: %v", err)
		}
		pub, ok := parsed.(*ecdsa.PublicKey)
		if !ok || pub.Curve != elliptic.P256() {
			t.Fatalf("exported key is %T on %v, want an *ecdsa.PublicKey on P-256", parsed, pub)
		}
		// The file is public by design and worthless if it is not: a private
		// half on disk would defeat the entire reason the key lives on a token.
		if strings.Contains(string(out), "PRIVATE") {
			t.Error("the exported file mentions PRIVATE")
		}
	})
}

// TestRunProvisionSigningKeyCmd_RejectsAnUnversionedLabelBeforeTouchingTheToken
// pins the ordering, not just the refusal. Key generation is irreversible,
// so a typo has to be caught while it still costs nothing (CLAUDE.md §3.9)
// — the evidence that it was is that no output file was created and no PIN
// was ever needed.
func TestRunProvisionSigningKeyCmd_RejectsAnUnversionedLabelBeforeTouchingTheToken(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		dir := t.TempDir()
		args := provisionArgs(t, b, dir, b.Label("image-signing-key"))
		// Unset the PIN variable the valid flag set exports: if the command
		// reaches the token at all, it now fails for that reason instead,
		// and this assertion would not be proving what it claims.
		t.Setenv("KEYTOOL_TEST_SIGNING_PIN", "")

		err := runProvisionSigningKeyCmd(args)
		if err == nil {
			t.Fatal("runProvisionSigningKeyCmd with an unversioned label succeeded, want an error")
		}
		if !strings.Contains(err.Error(), "versioned label") {
			t.Fatalf("error = %v, want it to name the versioned-label rule", err)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "signing.pub")); !os.IsNotExist(statErr) {
			t.Errorf("an output file was created despite the refusal: %v", statErr)
		}
	})
}

// TestRunProvisionSigningKeyCmd_RefusesToOverwriteAnExistingPublicKey covers
// the case where the file on disk is the *only* record of an earlier key
// whose label is now taken: overwriting it would destroy the only published
// way to verify anything that key has signed.
func TestRunProvisionSigningKeyCmd_RefusesToOverwriteAnExistingPublicKey(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		dir := t.TempDir()
		args := provisionArgs(t, b, dir, b.Label("image-signing-key-v1"))
		if err := os.WriteFile(filepath.Join(dir, "signing.pub"), []byte("pre-existing"), 0644); err != nil {
			t.Fatalf("WriteFile: %v", err)
		}

		if err := runProvisionSigningKeyCmd(args); err == nil {
			t.Fatal("runProvisionSigningKeyCmd with a pre-existing output file succeeded, want an error")
		}
		out, err := os.ReadFile(filepath.Join(dir, "signing.pub"))
		if err != nil {
			t.Fatalf("reading back the pre-existing file: %v", err)
		}
		if string(out) != "pre-existing" {
			t.Error("the pre-existing file was modified despite the refusal")
		}
	})
}

// TestRunProvisionSigningKeyCmd_RefusesTheCAsToken is Phase 4.8's
// third-token decision enforced where an operator will actually meet it:
// at the command line, before the key exists.
func TestRunProvisionSigningKeyCmd_RefusesTheCAsToken(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		dir := t.TempDir()

		// Put a CA key on the token first, through the harness's own
		// adapter — provisionArgs releases the module afterwards.
		caLabel := b.Label("ca-intermediate-key-v1")
		s, err := b.Adapter.OpenSession(ctx, b.Primary, pk11.SessionOptions{})
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		if err := b.Adapter.Login(ctx, s, []byte(b.PrimaryPIN), pk11.RoleUser); err != nil {
			t.Fatalf("Login: %v", err)
		}
		if _, err := b.Adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
			Curve: pk11.P256, Label: caLabel, Sign: true, Verify: true,
		}); err != nil {
			t.Fatalf("GenerateKeyPair(%s): %v", caLabel, err)
		}
		if err := b.Adapter.LogoutToken(ctx); err != nil {
			t.Fatalf("LogoutToken: %v", err)
		}
		if err := b.Adapter.CloseSession(ctx, s); err != nil {
			t.Fatalf("CloseSession: %v", err)
		}

		args := provisionArgs(t, b, dir, b.Label("image-signing-key-v1"))
		err = runProvisionSigningKeyCmd(args)
		if !errors.Is(err, signingkey.ErrCAHierarchyKeyPresent) {
			t.Fatalf("provisioning onto the CA's token = %v, want ErrCAHierarchyKeyPresent", err)
		}
		if _, statErr := os.Stat(filepath.Join(dir, "signing.pub")); !os.IsNotExist(statErr) {
			t.Errorf("an output file was created despite the refusal: %v", statErr)
		}
	})
}

// TestRun_RoutesTheProvisionSubcommand keeps the dispatch honest: a
// subcommand that exists in a file but not in run's switch is a command
// nobody can invoke. No token, so this does not multiply per backend.
func TestRun_RoutesTheProvisionSubcommand(t *testing.T) {
	// Missing every required flag, so it fails inside the subcommand rather
	// than at dispatch — which is exactly what distinguishes "routed" from
	// "unknown command".
	err := run([]string{"provision-signing-key"})
	if err == nil {
		t.Fatal("run(provision-signing-key) with no flags succeeded, want an error")
	}
	if strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("provision-signing-key is not routed by run: %v", err)
	}
}

// TestRunProvisionSigningKeyCmd_TwoRunsNeverProduceOneKey is the operator's
// real sequence: provision the image key, then provision the artifact key,
// each its own invocation and therefore its own C_Initialize.
//
// It exists because that sequence produced *one key under two labels* on a
// real backend. ProtectToolkit-C 7.3.3 in software emulation seeds its RNG
// per C_Initialize, so the first key pair generated after each library
// initialisation is byte-for-byte identical (measured 2026-09-04,
// docs/pkcs11-vendor-notes.md). Every attribute of the result was correct —
// distinct labels, distinct CKA_ID, sensitive, non-extractable — and the
// platform's purpose separation was gone.
//
// So this asserts the property rather than an outcome: two runs either
// produce two different keys, or the second run refuses. What it must never
// do is quietly hand back a duplicate, which is what it did before
// signingkey.Provision started checking.
func TestRunProvisionSigningKeyCmd_TwoRunsNeverProduceOneKey(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		dir := t.TempDir()
		first := provisionArgs(t, b, dir, b.Label("image-signing-key-v1"))
		if err := runProvisionSigningKeyCmd(first); err != nil {
			t.Fatalf("first invocation: %v", err)
		}
		imagePEM, err := os.ReadFile(filepath.Join(dir, "signing.pub"))
		if err != nil {
			t.Fatalf("reading the first public key: %v", err)
		}

		secondDir := t.TempDir()
		second := replaceFlag(provisionArgs(t, b, secondDir, b.Label("artifact-signing-key-v1")),
			"-public-key-out", filepath.Join(secondDir, "signing.pub"))

		switch err := runProvisionSigningKeyCmd(second); {
		case err == nil:
			artifactPEM, readErr := os.ReadFile(filepath.Join(secondDir, "signing.pub"))
			if readErr != nil {
				t.Fatalf("reading the second public key: %v", readErr)
			}
			if string(imagePEM) == string(artifactPEM) {
				t.Fatal("two invocations produced one key pair under two labels: " +
					"a compromise of the image key would also sign releases (CLAUDE.md §3.6)")
			}
		case errors.Is(err, signingkey.ErrDuplicateKey):
			// The token repeated itself and the platform refused. The
			// rejected key must also be gone: leaving it would take a label
			// that can now never be provisioned.
			if _, statErr := os.Stat(filepath.Join(secondDir, "signing.pub")); !os.IsNotExist(statErr) {
				t.Error("a public key file was written for a rejected duplicate")
			}
		default:
			t.Fatalf("second invocation: %v", err)
		}
	})
}
