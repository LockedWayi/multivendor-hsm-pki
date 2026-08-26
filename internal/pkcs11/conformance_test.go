package pkcs11_test

// TestConformance is the cross-vendor behavioral suite: every subtest here
// runs, unchanged, against every backend the environment makes available.
// SoftHSM2 needs no hardware and no proprietary SDK, so it is expected to
// always be present (inside the dev container — see CONTRIBUTING.md) and
// carries CI. ProtectServer requires a real Thales ProtectToolkit
// installation and is only exercised when PROTECTSERVER_MODULE is set
// (docs/protectserver-setup.md); with it unset, that backend's subtests
// skip and the suite stays green — the same graceful-skip pattern SoftHSM2
// itself uses when its module is absent.
//
// A single suite run against two independent implementations is the whole
// point of Phase 1 (see "Why two adapters rather than one" in
// docs/phases/phase-1-pkcs11-core.md): an abstraction validated once is a
// guess, and a bug that only one backend's adapter has is exactly what a
// shared test body — not two hand-copies of it — is built to catch.
//
// Every test vector here is a real digest, a real plaintext, a real key —
// never an all-zero or empty stand-in. That is not a style preference: an
// earlier diagnostic used make([]byte, 32) as a digest and produced a false
// "ProtectServer cannot verify signatures" finding, corrected in
// docs/pkcs11-vendor-notes.md. Degenerate vectors exercise exactly the
// edges where conforming implementations are allowed to disagree, so they
// manufacture divergences that no real call path ever hits.

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
	softhsm2SOPIN    = "000000"
	softhsm2UserPIN  = "123456"
	softhsm2WrongPIN = "000001"

	protectServerDefaultWorkspace = "hsm-pki-dev"
	protectServerWrongPIN         = "0000"
)

// conformanceBackend is one vendor's ready-to-use adapter, plus the
// credentials the suite needs to exercise it. runID is folded into every
// object label this run creates, so re-running the suite against a
// persistent token (ProtectServer's emulator token lives on disk between
// runs; SoftHSM2's is a fresh temp token every time, but the same
// discipline costs nothing there and keeps both paths identical) never
// finds a same-named leftover from a previous run and misreports it as a
// duplicate.
type conformanceBackend struct {
	name     string
	adapter  pk11.VendorAdapter
	ws       pk11.Workspace
	userPIN  []byte
	wrongPIN []byte
	runID    string
}

func (b *conformanceBackend) label(suffix string) string {
	return fmt.Sprintf("conf-%s-%s", b.runID, suffix)
}

// TestConformance runs the full behavioral suite against every available
// backend. See the package-level doc comment above for why.
func TestConformance(t *testing.T) {
	backends := []struct {
		name  string
		setup func(t *testing.T) *conformanceBackend
	}{
		{"SoftHSM2", setupSoftHSM2Backend},
		{"ProtectServer", setupProtectServerBackend},
	}
	for _, be := range backends {
		be := be
		t.Run(be.name, func(t *testing.T) {
			b := be.setup(t)
			runConformanceSuite(t, b)
		})
	}
}

// ─── SoftHSM2 backend setup ──────────────────────────────────────────────

func setupSoftHSM2Backend(t *testing.T) *conformanceBackend {
	t.Helper()
	modulePath := os.Getenv("SOFTHSM2_MODULE")
	explicit := modulePath != ""
	if modulePath == "" {
		modulePath = "/usr/lib/softhsm/libsofthsm2.so"
	}
	if _, err := os.Stat(modulePath); err != nil {
		if explicit {
			t.Fatalf("SOFTHSM2_MODULE=%s not found: %v", modulePath, err)
		}
		t.Skip("SoftHSM2 module not found at " + modulePath +
			" — run inside the dev container (see CONTRIBUTING.md)")
	}

	runID := fmt.Sprintf("%d", time.Now().UnixNano())
	label := "phase1-test-" + runID

	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		t.Fatalf("MkdirAll(tokenDir): %v", err)
	}
	confPath := filepath.Join(dir, "softhsm2.conf")
	conf := "directories.tokendir = " + tokenDir + "\n" +
		"objectstore.backend = file\n" +
		"log.level = ERROR\n"
	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		t.Fatalf("WriteFile(softhsm2.conf): %v", err)
	}
	// SOFTHSM2_CONF is process-wide; TestConformance's backends run
	// sequentially (never t.Parallel()), so there is no cross-backend race,
	// but a future parallelization of this suite would need to give each
	// backend its own subprocess or drop this shared-env approach.
	if err := os.Setenv("SOFTHSM2_CONF", confPath); err != nil {
		t.Fatalf("Setenv(SOFTHSM2_CONF): %v", err)
	}

	cmd := exec.Command("softhsm2-util", "--init-token", "--free",
		"--label", label, "--so-pin", softhsm2SOPIN, "--pin", softhsm2UserPIN)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("softhsm2-util --init-token: %v: %s", err, out)
	}

	adapter, err := pk11.NewSoftHSM2Adapter(modulePath)
	if err != nil {
		t.Fatalf("NewSoftHSM2Adapter: %v", err)
	}
	t.Cleanup(func() { adapter.Close() })

	ws, err := findWorkspace(adapter, label)
	if err != nil {
		t.Fatalf("Workspaces: %v", err)
	}

	return &conformanceBackend{
		name:     "SoftHSM2",
		adapter:  adapter,
		ws:       ws,
		userPIN:  []byte(softhsm2UserPIN),
		wrongPIN: []byte(softhsm2WrongPIN),
		runID:    runID,
	}
}

// ─── ProtectServer backend setup ─────────────────────────────────────────

func setupProtectServerBackend(t *testing.T) *conformanceBackend {
	t.Helper()
	modulePath := os.Getenv("PROTECTSERVER_MODULE")
	if modulePath == "" {
		t.Skip("PROTECTSERVER_MODULE not set — see docs/protectserver-setup.md " +
			"(this backend cannot run in public CI: proprietary SDK)")
	}

	label := os.Getenv("PROTECTSERVER_WORKSPACE")
	if label == "" {
		label = protectServerDefaultWorkspace
	}
	pin := os.Getenv("PROTECTSERVER_PIN")
	if pin == "" {
		t.Fatal("PROTECTSERVER_MODULE is set but PROTECTSERVER_PIN is not " +
			"— see docs/protectserver-setup.md")
	}

	adapter, err := pk11.NewProtectServerAdapter(modulePath)
	if err != nil {
		t.Fatalf("NewProtectServerAdapter: %v", err)
	}
	t.Cleanup(func() { adapter.Close() })

	ws, err := findWorkspace(adapter, label)
	if err != nil {
		t.Fatalf("Workspaces: %v", err)
	}

	return &conformanceBackend{
		name:     "ProtectServer",
		adapter:  adapter,
		ws:       ws,
		userPIN:  []byte(pin),
		wrongPIN: []byte(protectServerWrongPIN),
		runID:    fmt.Sprintf("%d", time.Now().UnixNano()),
	}
}

func findWorkspace(adapter pk11.VendorAdapter, label string) (pk11.Workspace, error) {
	wss, err := adapter.Workspaces(context.Background())
	if err != nil {
		return pk11.Workspace{}, err
	}
	for _, ws := range wss {
		if ws.Label == label {
			return ws, nil
		}
	}
	return pk11.Workspace{}, fmt.Errorf("workspace %q not found among %+v", label, wss)
}

// ─── The shared suite ─────────────────────────────────────────────────────

// openLoggedInSession opens a session on the backend's workspace, logs in
// as CKU_USER, and registers cleanup.
func (b *conformanceBackend) openLoggedInSession(t *testing.T, opts pk11.SessionOptions) *pk11.Session {
	t.Helper()
	ctx := context.Background()
	s, err := b.adapter.OpenSession(ctx, b.ws, opts)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	t.Cleanup(func() { _ = b.adapter.CloseSession(context.Background(), s) })

	if err := b.adapter.Login(ctx, s, append([]byte(nil), b.userPIN...), pk11.RoleUser); err != nil {
		t.Fatalf("Login: %v", err)
	}
	return s
}

// runConformanceSuite exercises the full VendorAdapter contract against b.
// Subtests run in declared order (Go runs t.Run subtests sequentially
// unless they call t.Parallel), which matters for the last one: closing
// b.adapter must happen after every other subtest, not before.
func runConformanceSuite(t *testing.T, b *conformanceBackend) {
	ctx := context.Background()

	t.Run("Workspaces_FindsTestToken", func(t *testing.T) {
		wss, err := b.adapter.Workspaces(ctx)
		if err != nil {
			t.Fatalf("Workspaces: %v", err)
		}
		for _, ws := range wss {
			if ws.Label == b.ws.Label && ws.Present {
				return
			}
		}
		t.Fatalf("workspace %q not found in %+v", b.ws.Label, wss)
	})

	t.Run("OpenSession_DefaultsAppliedOnZeroOptions", func(t *testing.T) {
		s, err := b.adapter.OpenSession(ctx, b.ws, pk11.SessionOptions{})
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		defer b.adapter.CloseSession(ctx, s)
		if got := s.Workspace(); got.SlotID != b.ws.SlotID {
			t.Fatalf("Workspace().SlotID = %d, want %d", got.SlotID, b.ws.SlotID)
		}
	})

	t.Run("Login_Success", func(t *testing.T) {
		s := b.openLoggedInSession(t, pk11.SessionOptions{})
		if !s.LoggedIn() {
			t.Fatal("LoggedIn() = false after successful Login")
		}
	})

	t.Run("Login_WrongPINFails", func(t *testing.T) {
		s, err := b.adapter.OpenSession(ctx, b.ws, pk11.SessionOptions{})
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		defer b.adapter.CloseSession(ctx, s)

		err = b.adapter.Login(ctx, s, append([]byte(nil), b.wrongPIN...), pk11.RoleUser)
		if err == nil {
			t.Fatal("Login with wrong PIN succeeded, want an error")
		}
		if s.LoggedIn() {
			t.Fatal("LoggedIn() = true after a failed Login")
		}
	})

	t.Run("Login_EmptyPINRejected", func(t *testing.T) {
		s, err := b.adapter.OpenSession(ctx, b.ws, pk11.SessionOptions{})
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		defer b.adapter.CloseSession(ctx, s)

		if err := b.adapter.Login(ctx, s, nil, pk11.RoleUser); err != pk11.ErrEmptyPIN {
			t.Fatalf("Login(nil pin) = %v, want ErrEmptyPIN", err)
		}
	})

	t.Run("Logout", func(t *testing.T) {
		s := b.openLoggedInSession(t, pk11.SessionOptions{})
		if err := b.adapter.Logout(ctx, s); err != nil {
			t.Fatalf("Logout: %v", err)
		}
		if s.LoggedIn() {
			t.Fatal("LoggedIn() = true after Logout")
		}
	})

	t.Run("Session_IdleTimeoutRejectsFurtherUse", func(t *testing.T) {
		s := b.openLoggedInSession(t, pk11.SessionOptions{
			IdleTimeout: 50 * time.Millisecond,
			MaxTTL:      time.Hour,
		})
		time.Sleep(100 * time.Millisecond)

		_, err := b.adapter.GenerateRandom(ctx, s, 8)
		if err != pk11.ErrSessionExpired {
			t.Fatalf("GenerateRandom after idle timeout = %v, want ErrSessionExpired", err)
		}
	})

	t.Run("Session_MaxTTLRejectsFurtherUse", func(t *testing.T) {
		s := b.openLoggedInSession(t, pk11.SessionOptions{
			IdleTimeout: time.Hour,
			MaxTTL:      50 * time.Millisecond,
		})
		time.Sleep(100 * time.Millisecond)

		_, err := b.adapter.GenerateRandom(ctx, s, 8)
		if err != pk11.ErrSessionExpired {
			t.Fatalf("GenerateRandom after max TTL = %v, want ErrSessionExpired", err)
		}
	})

	t.Run("CloseSession_RejectsFurtherUse", func(t *testing.T) {
		s, err := b.adapter.OpenSession(ctx, b.ws, pk11.SessionOptions{})
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		if err := b.adapter.CloseSession(ctx, s); err != nil {
			t.Fatalf("CloseSession: %v", err)
		}
		if _, err := b.adapter.GenerateRandom(ctx, s, 8); err != pk11.ErrSessionClosed {
			t.Fatalf("GenerateRandom after CloseSession = %v, want ErrSessionClosed", err)
		}
	})

	t.Run("CancelledContextRejected", func(t *testing.T) {
		cctx, cancel := context.WithCancel(ctx)
		cancel()
		if _, err := b.adapter.Workspaces(cctx); err == nil {
			t.Fatal("Workspaces with a cancelled context succeeded, want an error")
		}
	})

	t.Run("GenerateKeyPair_FindAndReadAttributes", func(t *testing.T) {
		s := b.openLoggedInSession(t, pk11.SessionOptions{})
		label := b.label("eckey")
		kp, err := b.adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
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

		found, err := b.adapter.FindObjects(ctx, s, []pk11.Attribute{
			pk11.NumericAttribute(pk11.AttrClass, uint64(pk11.ClassPrivateKey)),
			{Type: pk11.AttrLabel, Value: []byte(label)},
		})
		if err != nil {
			t.Fatalf("FindObjects: %v", err)
		}
		if len(found) != 1 || found[0] != kp.Private {
			t.Fatalf("FindObjects = %v, want exactly [%v]", found, kp.Private)
		}

		attrs, err := b.adapter.GetAttributes(ctx, s, kp.Public, []pk11.AttributeType{pk11.AttrLabel, pk11.AttrEcPoint})
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
	})

	t.Run("GenerateKeyPair_UnsupportedCurve", func(t *testing.T) {
		s := b.openLoggedInSession(t, pk11.SessionOptions{})
		_, err := b.adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
			Curve: pk11.ECCurve(99),
			Label: b.label("bad-curve"),
		})
		if err != pk11.ErrUnsupportedCurve {
			t.Fatalf("GenerateKeyPair with bad curve = %v, want ErrUnsupportedCurve", err)
		}
	})

	t.Run("GetAttributes_UnknownHandleFails", func(t *testing.T) {
		s := b.openLoggedInSession(t, pk11.SessionOptions{})
		_, err := b.adapter.GetAttributes(ctx, s, pk11.ObjectHandle(0xFFFFFFF), []pk11.AttributeType{pk11.AttrLabel})
		if err == nil {
			t.Fatal("GetAttributes on an unknown handle succeeded, want an error")
		}
	})

	t.Run("SignVerify_ECDSARoundTrip", func(t *testing.T) {
		s := b.openLoggedInSession(t, pk11.SessionOptions{})
		kp, err := b.adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
			Curve: pk11.P256, Label: b.label("sign"), Sign: true, Verify: true,
		})
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}

		// A real SHA-256 digest of real data — never an all-zero or
		// otherwise degenerate stand-in. See the package doc comment.
		digest := sha256.Sum256([]byte("hsm-pki-platform " + b.name + " conformance"))
		sig, err := b.adapter.Sign(ctx, s, kp.Private, pk11.Mechanism{Type: pk11.MechECDSA}, digest[:])
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		if len(sig) == 0 {
			t.Fatal("Sign returned an empty signature")
		}

		if err := b.adapter.Verify(ctx, s, kp.Public, pk11.Mechanism{Type: pk11.MechECDSA}, digest[:], sig); err != nil {
			t.Fatalf("Verify (device-side) = %v, want nil", err)
		}

		// Cross-check the HSM's raw r||s signature against Go's own ECDSA
		// verifier, using the public key read back off the HSM — this
		// proves the produced signature is standards-conformant, not just
		// internally self-consistent.
		attrs, err := b.adapter.GetAttributes(ctx, s, kp.Public, []pk11.AttributeType{pk11.AttrEcPoint})
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
		if err := b.adapter.Verify(ctx, s, kp.Public, pk11.Mechanism{Type: pk11.MechECDSA}, digest[:], sig); err == nil {
			t.Fatal("Verify accepted a signature over a tampered digest")
		}
	})

	t.Run("EncryptDecrypt_AESRoundTrip", func(t *testing.T) {
		s := b.openLoggedInSession(t, pk11.SessionOptions{})
		key, err := b.adapter.GenerateSecretKey(ctx, s, pk11.SecretKeyRequest{
			KeyBits: 256, Label: b.label("aes"), Encrypt: true, Decrypt: true,
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

		ct, err := b.adapter.Encrypt(ctx, s, key, mech, plaintext)
		if err != nil {
			t.Fatalf("Encrypt: %v", err)
		}
		if string(ct) == string(plaintext) {
			t.Fatal("ciphertext equals plaintext")
		}

		pt, err := b.adapter.Decrypt(ctx, s, key, mech, ct)
		if err != nil {
			t.Fatalf("Decrypt: %v", err)
		}
		if string(pt) != string(plaintext) {
			t.Fatalf("Decrypt = %q, want %q", pt, plaintext)
		}
	})

	t.Run("WrapUnwrap_AESKeyWrapRoundTrip", func(t *testing.T) {
		s := b.openLoggedInSession(t, pk11.SessionOptions{})
		wrappingKey, err := b.adapter.GenerateSecretKey(ctx, s, pk11.SecretKeyRequest{
			KeyBits: 256, Label: b.label("wrap-key"), Wrap: true, Unwrap: true,
		})
		if err != nil {
			t.Fatalf("GenerateSecretKey (wrapping key): %v", err)
		}
		keyToWrap, err := b.adapter.GenerateSecretKey(ctx, s, pk11.SecretKeyRequest{
			KeyBits: 128, Label: b.label("payload-key"), Extractable: true, Encrypt: true, Decrypt: true,
		})
		if err != nil {
			t.Fatalf("GenerateSecretKey (payload key): %v", err)
		}

		mech := pk11.Mechanism{Type: pk11.MechAESKeyWrap}
		wrapped, err := b.adapter.Wrap(ctx, s, wrappingKey, keyToWrap, mech)
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		if len(wrapped) == 0 {
			t.Fatal("Wrap returned empty ciphertext")
		}

		unwrapped, err := b.adapter.Unwrap(ctx, s, wrappingKey, mech, wrapped, []pk11.Attribute{
			pk11.NumericAttribute(pk11.AttrClass, uint64(pk11.ClassSecretKey)),
			pk11.NumericAttribute(pk11.AttrKeyType, uint64(pk11.KeyTypeAES)),
			{Type: pk11.AttrLabel, Value: []byte(b.label("payload-key-restored"))},
			{Type: pk11.AttrDecrypt, Value: []byte{1}},
		})
		if err != nil {
			t.Fatalf("Unwrap: %v", err)
		}
		if unwrapped == 0 {
			t.Fatal("Unwrap returned a zero handle")
		}
	})

	t.Run("GenerateRandom_ReturnsDistinctBytes", func(t *testing.T) {
		s := b.openLoggedInSession(t, pk11.SessionOptions{})
		a, err := b.adapter.GenerateRandom(ctx, s, 32)
		if err != nil {
			t.Fatalf("GenerateRandom: %v", err)
		}
		if len(a) != 32 {
			t.Fatalf("GenerateRandom returned %d bytes, want 32", len(a))
		}
		c, err := b.adapter.GenerateRandom(ctx, s, 32)
		if err != nil {
			t.Fatalf("GenerateRandom: %v", err)
		}
		if string(a) == string(c) {
			t.Fatal("two GenerateRandom calls returned identical output")
		}
	})

	// AdapterClose must run last: PKCS#11's C_Initialize is a per-module,
	// per-process resource, so a second Ctx over the same .so path while
	// this one is still live would fail with CKR_CRYPTOKI_ALREADY_INITIALIZED
	// — there is no way to test Close() on a disposable second instance
	// without that collision. Naming this subtest last (t.Run calls run in
	// declared order) keeps every earlier subtest's use of b.adapter valid.
	// t.Cleanup's own Close() call after this is a no-op since Close is
	// idempotent.
	t.Run("AdapterClose_RejectsFurtherUse", func(t *testing.T) {
		if err := b.adapter.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
		if err := b.adapter.Close(); err != nil {
			t.Fatalf("second Close() = %v, want nil (idempotent)", err)
		}
		if _, err := b.adapter.Workspaces(ctx); err != pk11.ErrAdapterClosed {
			t.Fatalf("Workspaces after Close = %v, want ErrAdapterClosed", err)
		}
	})
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
