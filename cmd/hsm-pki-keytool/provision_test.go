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

	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/signingkey"
)

// provisionArgs builds a complete, valid flag set and releases the
// harness's adapter, because the command opens the module itself.
// Anything a test puts on the token happens before this is called.
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
// command as an operator does and reads its output through the standard
// library's generic PKIX path, as a verifier would.
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
		// No private half on disk.
		if strings.Contains(string(out), "PRIVATE") {
			t.Error("the exported file mentions PRIVATE")
		}
	})
}

// TestRunProvisionSigningKeyCmd_RejectsAnUnversionedLabelBeforeTouchingTheToken
// pins the ordering: no output file is created and no PIN is needed.
func TestRunProvisionSigningKeyCmd_RejectsAnUnversionedLabelBeforeTouchingTheToken(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		dir := t.TempDir()
		args := provisionArgs(t, b, dir, b.Label("image-signing-key"))
		// With the PIN unset, reaching the token would fail for that reason
		// instead.
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

// TestRunProvisionSigningKeyCmd_RefusesToOverwriteAnExistingPublicKey: the
// file may be the only record of a key whose label is taken.
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

// TestRunProvisionSigningKeyCmd_RefusesTheCAsToken: the separate-token
// rule, enforced at the command line before the key exists.
func TestRunProvisionSigningKeyCmd_RefusesTheCAsToken(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		ctx := context.Background()
		dir := t.TempDir()

		// A CA key on the token first, through the harness's adapter.
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

// TestRun_RoutesTheProvisionSubcommand: a subcommand missing from run's
// switch cannot be invoked. No token.
func TestRun_RoutesTheProvisionSubcommand(t *testing.T) {
	// Missing every required flag, so it fails inside the subcommand.
	err := run([]string{"provision-signing-key"})
	if err == nil {
		t.Fatal("run(provision-signing-key) with no flags succeeded, want an error")
	}
	if strings.Contains(err.Error(), "unknown command") {
		t.Fatalf("provision-signing-key is not routed by run: %v", err)
	}
}

// TestRunProvisionSigningKeyCmd_TwoRunsNeverProduceOneKey: provision the
// image key, then the artifact key, each its own invocation and its own
// C_Initialize. On ProtectToolkit-C 7.3.3 software emulation this produced
// one key under two labels, with every attribute correct. Two runs either
// produce two keys or the second refuses.
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
					"a compromise of the image key would also sign releases")
			}
		case errors.Is(err, signingkey.ErrDuplicateKey):
			// No public key was published for the rejected key, and the
			// rejected key is gone from the token, so its label can be used
			// again.
			if _, statErr := os.Stat(filepath.Join(secondDir, "signing.pub")); !os.IsNotExist(statErr) {
				t.Error("a public key file was written for a rejected duplicate")
			}
			assertLabelIsFree(t, b, b.Label("artifact-signing-key-v1"))
		default:
			t.Fatalf("second invocation: %v", err)
		}
	})
}

// assertLabelIsFree reopens the module and confirms neither half of a key
// pair exists under label.
func assertLabelIsFree(t *testing.T, b *hsmtest.Backend, label string) {
	t.Helper()
	ctx := context.Background()
	adapter, err := newVendorAdapter(b.AdapterName, b.ModulePath)
	if err != nil {
		t.Fatalf("reopening the module: %v", err)
	}
	defer adapter.Close()
	ws, err := findWorkspace(ctx, adapter, b.Primary.Label, "")
	if err != nil {
		t.Fatalf("findWorkspace: %v", err)
	}
	if err := adapter.LoginToken(ctx, ws, []byte(b.PrimaryPIN), pk11.RoleUser); err != nil {
		t.Fatalf("LoginToken: %v", err)
	}
	defer func() { _ = adapter.LogoutToken(ctx) }()
	s, err := adapter.OpenSession(ctx, ws, pk11.DefaultSessionOptions())
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer func() { _ = adapter.CloseSession(ctx, s) }()

	for _, class := range []pk11.ObjectClass{pk11.ClassPublicKey, pk11.ClassPrivateKey} {
		free, err := pk11.LabelIsFree(ctx, adapter, s, class, label)
		if err != nil {
			t.Fatalf("LabelIsFree(class=%d): %v", class, err)
		}
		if !free {
			t.Errorf("label %q (class %d) still exists after the duplicate was rejected; "+
				"the version number is now burnt and can never be provisioned", label, class)
		}
	}
}

// TestTokenRNG_ReseedsAcrossInitializeOrTheDuplicateCheckCatchesIt: a
// token that reseeds gives two different keys; ProtectToolkit-C 7.3.3
// software emulation gives the same key twice, and C_GenerateRandom
// repeats too. Either is fine. Two labels naming one key pair is not. The
// test asserts the disjunction and logs which branch the backend took.
func TestTokenRNG_ReseedsAcrossInitializeOrTheDuplicateCheckCatchesIt(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		firstDir, secondDir := t.TempDir(), t.TempDir()
		firstLabel := b.Label("image-signing-key-v20")
		secondLabel := b.Label("artifact-signing-key-v20")

		if err := runProvisionSigningKeyCmd(provisionArgs(t, b, firstDir, firstLabel)); err != nil {
			t.Fatalf("first invocation: %v", err)
		}
		first, err := os.ReadFile(filepath.Join(firstDir, "signing.pub"))
		if err != nil {
			t.Fatalf("reading the first public key: %v", err)
		}

		err = runProvisionSigningKeyCmd(provisionArgs(t, b, secondDir, secondLabel))
		switch {
		case err == nil:
			second, readErr := os.ReadFile(filepath.Join(secondDir, "signing.pub"))
			if readErr != nil {
				t.Fatalf("reading the second public key: %v", readErr)
			}
			if string(first) == string(second) {
				t.Fatal("two processes produced one key pair and the duplicate check did not catch it")
			}
			t.Logf("%s: the token reseeds across C_Initialize; two processes, two keys", b.Name)
		case errors.Is(err, signingkey.ErrDuplicateKey):
			t.Logf("%s: the token repeated its first key across C_Initialize; the duplicate check refused it, "+
				"which is why this backend must not be used to provision keys anyone relies on", b.Name)
			assertLabelIsFree(t, b, secondLabel)
		default:
			t.Fatalf("second invocation failed for an unrelated reason: %v", err)
		}
	})
}
