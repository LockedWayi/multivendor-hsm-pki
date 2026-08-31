package pkcs11_test

// These integration tests run entirely against SoftHSM2 — no vendor
// hardware is touched (CLAUDE.md §2, docs/phases/phase-1-pkcs11-core.md).
// They require the SoftHSM2 PKCS#11 module to be installed; run them
// inside the project's dev container (see CONTRIBUTING.md) or on any host
// with `softhsm2` and `opensc`/`softhsm2-util` installed.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

const (
	testTokenLabel = "phase1-test"
	testSOPIN      = "000000"
	testUserPIN    = "123456"
	testWrongPIN   = "000001"
)

var (
	testAdapter *pk11.SoftHSM2Adapter
	testWS      pk11.Workspace

	// skipReason is set by TestMain when SoftHSM2 is unavailable. The
	// pure-logic tests in session_test.go and secure_pin_test.go share
	// this test binary and must still run in that case — only the tests
	// that need a real PKCS#11 module call requireSoftHSM2 and skip.
	skipReason string
)

func TestMain(m *testing.M) {
	modulePath := os.Getenv("SOFTHSM2_MODULE")
	explicit := modulePath != ""
	if modulePath == "" {
		modulePath = "/usr/lib/softhsm/libsofthsm2.so"
	}
	if _, err := os.Stat(modulePath); err != nil {
		if explicit {
			fmt.Fprintf(os.Stderr, "SOFTHSM2_MODULE=%s not found: %v\n", modulePath, err)
			os.Exit(1)
		}
		skipReason = "SoftHSM2 module not found at " + modulePath +
			" — run inside the dev container (see CONTRIBUTING.md)"
		os.Exit(m.Run())
	}

	if err := provisionToken(); err != nil {
		fmt.Fprintf(os.Stderr, "provisioning SoftHSM2 test token: %v\n", err)
		os.Exit(1)
	}

	var err error
	testAdapter, err = pk11.NewSoftHSM2Adapter(modulePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "NewSoftHSM2Adapter: %v\n", err)
		os.Exit(1)
	}

	wss, err := testAdapter.Workspaces(context.Background())
	if err != nil {
		fmt.Fprintf(os.Stderr, "Workspaces: %v\n", err)
		os.Exit(1)
	}
	found := false
	for _, ws := range wss {
		if ws.Label == testTokenLabel {
			testWS = ws
			found = true
			break
		}
	}
	if !found {
		fmt.Fprintf(os.Stderr, "test token %q not found among workspaces: %+v\n", testTokenLabel, wss)
		os.Exit(1)
	}

	code := m.Run()
	testAdapter.Close()
	os.Exit(code)
}

// requireSoftHSM2 skips the calling test when no SoftHSM2 module was found
// (see TestMain). Every test in this file that touches testAdapter calls
// this first.
func requireSoftHSM2(t *testing.T) {
	t.Helper()
	if skipReason != "" {
		t.Skip(skipReason)
	}
}

// provisionToken creates a fresh, isolated SoftHSM2 token store per test
// run (via a temp-dir SOFTHSM2_CONF) so tests never depend on — or
// collide with — whatever tokens happen to exist on the host.
func provisionToken() error {
	dir, err := os.MkdirTemp("", "softhsm2-test-*")
	if err != nil {
		return err
	}
	tokenDir := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		return err
	}
	confPath := filepath.Join(dir, "softhsm2.conf")
	conf := "directories.tokendir = " + tokenDir + "\n" +
		"objectstore.backend = file\n" +
		"log.level = ERROR\n"
	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		return err
	}
	if err := os.Setenv("SOFTHSM2_CONF", confPath); err != nil {
		return err
	}

	cmd := exec.Command("softhsm2-util", "--init-token", "--free",
		"--label", testTokenLabel, "--so-pin", testSOPIN, "--pin", testUserPIN)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("softhsm2-util --init-token: %w: %s", err, out)
	}
	return nil
}

// openLoggedInSession opens a session on the shared test workspace, logs
// in as CKU_USER, and registers cleanup — tests should call this instead
// of duplicating the open+login+close dance.
func openLoggedInSession(t *testing.T, opts pk11.SessionOptions) *pk11.Session {
	t.Helper()
	requireSoftHSM2(t)
	ctx := context.Background()
	s, err := testAdapter.OpenSession(ctx, testWS, opts)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	t.Cleanup(func() { _ = testAdapter.CloseSession(context.Background(), s) })

	pin := []byte(testUserPIN)
	if err := testAdapter.Login(ctx, s, pin, pk11.RoleUser); err != nil {
		t.Fatalf("Login: %v", err)
	}
	return s
}

// ─── Workspaces ─────────────────────────────────────────────────────────

func TestWorkspaces_FindsTestToken(t *testing.T) {
	requireSoftHSM2(t)
	wss, err := testAdapter.Workspaces(context.Background())
	if err != nil {
		t.Fatalf("Workspaces: %v", err)
	}
	for _, ws := range wss {
		if ws.Label == testTokenLabel && ws.Present {
			return
		}
	}
	t.Fatalf("test token %q not found in %+v", testTokenLabel, wss)
}

// ─── Session lifecycle / Login / Logout ─────────────────────────────────

func TestOpenSession_DefaultsAppliedOnZeroOptions(t *testing.T) {
	requireSoftHSM2(t)
	s, err := testAdapter.OpenSession(context.Background(), testWS, pk11.SessionOptions{})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer testAdapter.CloseSession(context.Background(), s)

	if got := s.Workspace(); got.SlotID != testWS.SlotID {
		t.Fatalf("Workspace().SlotID = %d, want %d", got.SlotID, testWS.SlotID)
	}
}

func TestLogin_Success(t *testing.T) {
	s := openLoggedInSession(t, pk11.SessionOptions{})
	if !s.LoggedIn() {
		t.Fatal("LoggedIn() = false after successful Login")
	}
}

func TestLogin_WrongPINFails(t *testing.T) {
	requireSoftHSM2(t)
	ctx := context.Background()
	s, err := testAdapter.OpenSession(ctx, testWS, pk11.SessionOptions{})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer testAdapter.CloseSession(ctx, s)

	err = testAdapter.Login(ctx, s, []byte(testWrongPIN), pk11.RoleUser)
	if err == nil {
		t.Fatal("Login with wrong PIN succeeded, want an error")
	}
	if s.LoggedIn() {
		t.Fatal("LoggedIn() = true after a failed Login")
	}
}

func TestLogin_EmptyPINRejected(t *testing.T) {
	requireSoftHSM2(t)
	ctx := context.Background()
	s, err := testAdapter.OpenSession(ctx, testWS, pk11.SessionOptions{})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer testAdapter.CloseSession(ctx, s)

	if err := testAdapter.Login(ctx, s, nil, pk11.RoleUser); err != pk11.ErrEmptyPIN {
		t.Fatalf("Login(nil pin) = %v, want ErrEmptyPIN", err)
	}
}

func TestLogout(t *testing.T) {
	s := openLoggedInSession(t, pk11.SessionOptions{})
	if err := testAdapter.Logout(context.Background(), s); err != nil {
		t.Fatalf("Logout: %v", err)
	}
	if s.LoggedIn() {
		t.Fatal("LoggedIn() = true after Logout")
	}
}

func TestSession_IdleTimeoutRejectsFurtherUse(t *testing.T) {
	s := openLoggedInSession(t, pk11.SessionOptions{
		IdleTimeout: 30 * time.Millisecond,
		MaxTTL:      time.Hour,
	})
	time.Sleep(60 * time.Millisecond)

	_, err := testAdapter.GenerateRandom(context.Background(), s, 8)
	if err != pk11.ErrSessionExpired {
		t.Fatalf("GenerateRandom after idle timeout = %v, want ErrSessionExpired", err)
	}
}

func TestSession_MaxTTLRejectsFurtherUse(t *testing.T) {
	s := openLoggedInSession(t, pk11.SessionOptions{
		IdleTimeout: time.Hour,
		MaxTTL:      30 * time.Millisecond,
	})
	time.Sleep(60 * time.Millisecond)

	_, err := testAdapter.GenerateRandom(context.Background(), s, 8)
	if err != pk11.ErrSessionExpired {
		t.Fatalf("GenerateRandom after max TTL = %v, want ErrSessionExpired", err)
	}
}

func TestCloseSession_RejectsFurtherUse(t *testing.T) {
	requireSoftHSM2(t)
	ctx := context.Background()
	s, err := testAdapter.OpenSession(ctx, testWS, pk11.SessionOptions{})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	if err := testAdapter.CloseSession(ctx, s); err != nil {
		t.Fatalf("CloseSession: %v", err)
	}
	if _, err := testAdapter.GenerateRandom(ctx, s, 8); err != pk11.ErrSessionClosed {
		t.Fatalf("GenerateRandom after CloseSession = %v, want ErrSessionClosed", err)
	}
}

func TestCancelledContextRejected(t *testing.T) {
	requireSoftHSM2(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := testAdapter.Workspaces(ctx); err == nil {
		t.Fatal("Workspaces with a cancelled context succeeded, want an error")
	}
}

// ─── Key generation, find, attributes ────────────────────────────────────

func TestGenerateKeyPair_FindAndReadAttributes(t *testing.T) {
	ctx := context.Background()
	s := openLoggedInSession(t, pk11.SessionOptions{})

	label := "phase1-eckey"
	kp, err := testAdapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
		Curve:  pk11.P256,
		Label:  label,
		Sign:   true,
		Verify: true,
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if kp.Public == 0 || kp.Private == 0 {
		t.Fatalf("GenerateKeyPair returned zero handle: %+v", kp)
	}

	found, err := testAdapter.FindObjects(ctx, s, []pk11.Attribute{
		pk11.NumericAttribute(pk11.AttrClass, uint64(pk11.ClassPrivateKey)),
		{Type: pk11.AttrLabel, Value: []byte(label)},
	})
	if err != nil {
		t.Fatalf("FindObjects: %v", err)
	}
	if len(found) != 1 || found[0] != kp.Private {
		t.Fatalf("FindObjects = %v, want exactly [%v]", found, kp.Private)
	}

	attrs, err := testAdapter.GetAttributes(ctx, s, kp.Public, []pk11.AttributeType{pk11.AttrLabel, pk11.AttrEcPoint})
	if err != nil {
		t.Fatalf("GetAttributes: %v", err)
	}
	var gotLabel string
	var ecPoint []byte
	for _, a := range attrs {
		switch a.Type {
		case pk11.AttrLabel:
			gotLabel = string(a.Value)
		case pk11.AttrEcPoint:
			ecPoint = a.Value
		}
	}
	if gotLabel != label {
		t.Fatalf("CKA_LABEL = %q, want %q", gotLabel, label)
	}
	if len(ecPoint) == 0 {
		t.Fatal("CKA_EC_POINT was empty")
	}
}

func TestGenerateKeyPair_UnsupportedCurve(t *testing.T) {
	s := openLoggedInSession(t, pk11.SessionOptions{})
	_, err := testAdapter.GenerateKeyPair(context.Background(), s, pk11.KeyPairRequest{
		Curve: pk11.ECCurve(99),
		Label: "bad-curve",
	})
	if err != pk11.ErrUnsupportedCurve {
		t.Fatalf("GenerateKeyPair with bad curve = %v, want ErrUnsupportedCurve", err)
	}
}

func TestGetAttributes_UnknownHandleFails(t *testing.T) {
	s := openLoggedInSession(t, pk11.SessionOptions{})
	_, err := testAdapter.GetAttributes(context.Background(), s, pk11.ObjectHandle(0xFFFFFFF), []pk11.AttributeType{pk11.AttrLabel})
	if err == nil {
		t.Fatal("GetAttributes on an unknown handle succeeded, want an error")
	}
}

// ─── Sign / Verify ────────────────────────────────────────────────────────

func TestSignVerify_ECDSARoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openLoggedInSession(t, pk11.SessionOptions{})

	kp, err := testAdapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
		Curve: pk11.P256, Label: "sign-test", Sign: true, Verify: true,
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	digest := sha256.Sum256([]byte("hsm-pki-platform phase 1"))
	sig, err := testAdapter.Sign(ctx, s, kp.Private, pk11.Mechanism{Type: pk11.MechECDSA}, digest[:])
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if len(sig) == 0 {
		t.Fatal("Sign returned an empty signature")
	}

	if err := testAdapter.Verify(ctx, s, kp.Public, pk11.Mechanism{Type: pk11.MechECDSA}, digest[:], sig); err != nil {
		t.Fatalf("Verify (device-side) = %v, want nil", err)
	}

	// Cross-check the HSM's raw r||s signature against Go's own ECDSA
	// verifier, using the public key read back off the HSM — this proves
	// the produced signature is standards-conformant, not just internally
	// self-consistent.
	attrs, err := testAdapter.GetAttributes(ctx, s, kp.Public, []pk11.AttributeType{pk11.AttrEcPoint})
	if err != nil {
		t.Fatalf("GetAttributes: %v", err)
	}
	pub, err := ecPointToPublicKey(elliptic.P256(), attrs[0].Value)
	if err != nil {
		t.Fatalf("ecPointToPublicKey: %v", err)
	}
	half := len(sig) / 2
	r := new(big.Int).SetBytes(sig[:half])
	s2 := new(big.Int).SetBytes(sig[half:])
	if !ecdsa.Verify(pub, digest[:], r, s2) {
		t.Fatal("crypto/ecdsa.Verify rejected the HSM-produced signature")
	}

	// Tamper with the digest — verification must fail, not silently pass.
	digest[0] ^= 0xFF
	if err := testAdapter.Verify(ctx, s, kp.Public, pk11.Mechanism{Type: pk11.MechECDSA}, digest[:], sig); err == nil {
		t.Fatal("Verify accepted a signature over a tampered digest")
	}
}

// ─── Encrypt / Decrypt, Wrap / Unwrap, GenerateRandom ────────────────────

func TestEncryptDecrypt_AESRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openLoggedInSession(t, pk11.SessionOptions{})

	key, err := testAdapter.GenerateSecretKey(ctx, s, pk11.SecretKeyRequest{
		KeyBits: 256, Label: "aes-test", Encrypt: true, Decrypt: true,
	})
	if err != nil {
		t.Fatalf("GenerateSecretKey: %v", err)
	}

	iv := make([]byte, 16)
	if _, err := rand.Read(iv); err != nil {
		t.Fatalf("rand.Read(iv): %v", err)
	}
	mech := pk11.Mechanism{Type: pk11.MechAESCBCPad, Param: iv}
	plaintext := []byte("private keys never touch plaintext disk or logs")

	ct, err := testAdapter.Encrypt(ctx, s, key, mech, plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}
	if string(ct) == string(plaintext) {
		t.Fatal("ciphertext equals plaintext")
	}

	pt, err := testAdapter.Decrypt(ctx, s, key, mech, ct)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}
	if string(pt) != string(plaintext) {
		t.Fatalf("Decrypt = %q, want %q", pt, plaintext)
	}
}

func TestWrapUnwrap_AESKeyWrapRoundTrip(t *testing.T) {
	ctx := context.Background()
	s := openLoggedInSession(t, pk11.SessionOptions{})

	wrappingKey, err := testAdapter.GenerateSecretKey(ctx, s, pk11.SecretKeyRequest{
		KeyBits: 256, Label: "wrapping-key", Wrap: true, Unwrap: true,
	})
	if err != nil {
		t.Fatalf("GenerateSecretKey (wrapping key): %v", err)
	}
	keyToWrap, err := testAdapter.GenerateSecretKey(ctx, s, pk11.SecretKeyRequest{
		KeyBits: 128, Label: "payload-key", Extractable: true, Encrypt: true, Decrypt: true,
	})
	if err != nil {
		t.Fatalf("GenerateSecretKey (payload key): %v", err)
	}

	mech := pk11.Mechanism{Type: pk11.MechAESKeyWrap}
	wrapped, err := testAdapter.Wrap(ctx, s, wrappingKey, keyToWrap, mech)
	if err != nil {
		t.Fatalf("Wrap: %v", err)
	}
	if len(wrapped) == 0 {
		t.Fatal("Wrap returned empty ciphertext")
	}

	unwrapped, err := testAdapter.Unwrap(ctx, s, wrappingKey, mech, wrapped, []pk11.Attribute{
		pk11.NumericAttribute(pk11.AttrClass, uint64(pk11.ClassSecretKey)),
		pk11.NumericAttribute(pk11.AttrKeyType, uint64(pk11.KeyTypeAES)),
		{Type: pk11.AttrLabel, Value: []byte("payload-key-restored")},
		{Type: pk11.AttrDecrypt, Value: []byte{1}},
	})
	if err != nil {
		t.Fatalf("Unwrap: %v", err)
	}
	if unwrapped == 0 {
		t.Fatal("Unwrap returned a zero handle")
	}
}

func TestGenerateRandom_ReturnsDistinctBytes(t *testing.T) {
	s := openLoggedInSession(t, pk11.SessionOptions{})
	ctx := context.Background()

	a, err := testAdapter.GenerateRandom(ctx, s, 32)
	if err != nil {
		t.Fatalf("GenerateRandom: %v", err)
	}
	if len(a) != 32 {
		t.Fatalf("GenerateRandom returned %d bytes, want 32", len(a))
	}
	b, err := testAdapter.GenerateRandom(ctx, s, 32)
	if err != nil {
		t.Fatalf("GenerateRandom: %v", err)
	}
	if string(a) == string(b) {
		t.Fatal("two GenerateRandom calls returned identical output")
	}
}

// ─── Adapter teardown ─────────────────────────────────────────────────────
//
// TestZZZAdapterClose must run last and must close testAdapter itself
// rather than a second instance: PKCS#11's C_Initialize is a per-module,
// per-process resource — SoftHSM2's shared library is loaded once (dlopen
// reference-counts the same path), so a second Ctx initializing the same
// .so path while the first is still live fails with
// CKR_CRYPTOKI_ALREADY_INITIALIZED. That is a real constraint of the
// PKCS#11 module model, not a flaw in this adapter's one-instance-per-
// vendor design — two adapters for two *different* vendor .so files remain
// fully independent. `go test` runs a package's tests in source order, so
// naming this last (alphabetically among these tests, and physically last
// in the file) keeps every other test's use of the shared testAdapter
// valid. TestMain's own Close() call after m.Run() is a no-op here since
// Close is idempotent.

func TestZZZAdapterClose_RejectsFurtherUse(t *testing.T) {
	requireSoftHSM2(t)
	if err := testAdapter.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := testAdapter.Close(); err != nil {
		t.Fatalf("second Close() = %v, want nil (idempotent)", err)
	}
	if _, err := testAdapter.Workspaces(context.Background()); err != pk11.ErrAdapterClosed {
		t.Fatalf("Workspaces after Close = %v, want ErrAdapterClosed", err)
	}
}

// ─── Helpers ───────────────────────────────────────────────────────────────

// ecPointToPublicKey decodes a PKCS#11 CKA_EC_POINT (a DER OCTET STRING
// wrapping an uncompressed EC point) into a crypto/ecdsa public key.
func ecPointToPublicKey(curve elliptic.Curve, ecPoint []byte) (*ecdsa.PublicKey, error) {
	var raw []byte
	if len(ecPoint) > 2 && ecPoint[0] == 0x04 {
		// ASN.1 OCTET STRING header: 0x04 <len> <point bytes>.
		n := int(ecPoint[1])
		if n <= len(ecPoint)-2 {
			raw = ecPoint[2 : 2+n]
		}
	}
	if raw == nil {
		raw = ecPoint // some tokens return the raw point unwrapped
	}
	x, y := elliptic.Unmarshal(curve, raw)
	if x == nil {
		return nil, fmt.Errorf("invalid EC point encoding (%d bytes)", len(ecPoint))
	}
	return &ecdsa.PublicKey{Curve: curve, X: x, Y: y}, nil
}
