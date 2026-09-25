package pkcs11_test

// TestConformance is the cross-vendor suite: every subtest runs, unchanged,
// against every backend the environment provides. SoftHSM2 is always
// present in the dev container and carries CI. ProtectServer runs when
// PROTECTSERVER_MODULE is set and Luna when LUNA_MODULE is; each skips
// with its module variable unset and fails with it set and the rest of its
// variables missing.
//
// Every test vector is a real digest, a real plaintext, a real key, never
// an all-zero stand-in. An all-zero digest is a case where conforming
// implementations may disagree, and one produced a false "ProtectServer
// cannot verify" finding once.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"math/big"
	"strings"
	"sync"
	"testing"
	"time"

	p11 "github.com/miekg/pkcs11"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// conformanceBackend is one vendor's adapter plus the credentials the
// suite needs. runID is folded into every object label, so a persistent
// token never shows a leftover from an earlier run as a duplicate.
type conformanceBackend struct {
	name     string
	adapter  pk11.VendorAdapter
	ws       pk11.Workspace
	userPIN  []byte
	wrongPIN []byte
	// role is the login identity every login in the suite uses. Set
	// explicitly for every backend: Role's zero value is CKU_SO.
	role pk11.Role
	// caps is the adapter's own declaration. Every field is measured by a
	// subtest below; a declaration the token no longer matches is a
	// failing test, not a silent skip.
	caps        pk11.Capabilities
	adapterName string
	modulePath  string
	runID       string
	// reopen builds a second connection to the same module, for the case
	// where cleanup cannot use the first one. See registerCleanup.
	reopen func() (pk11.VendorAdapter, error)
}

func (b *conformanceBackend) label(suffix string) string {
	return fmt.Sprintf("conf-%s-%s", b.runID, suffix)
}

// TestConformance runs the full suite against every backend the
// internal/hsmtest registry provides, in its single-token shape.
func TestConformance(t *testing.T) {
	hsmtest.ForEachSingle(t, func(t *testing.T, s *hsmtest.Single) {
		runConformanceSuite(t, newConformanceBackend(t, s))
	})
}

func newConformanceBackend(t *testing.T, s *hsmtest.Single) *conformanceBackend {
	t.Helper()
	b := &conformanceBackend{
		name:        s.Name,
		adapter:     s.Adapter,
		ws:          s.Workspace,
		userPIN:     s.PIN,
		wrongPIN:    s.WrongPIN,
		role:        s.Role,
		caps:        s.Adapter.Capabilities(),
		adapterName: s.AdapterName,
		modulePath:  s.ModulePath,
		runID:       s.RunID,
		reopen:      s.Reopen,
	}
	b.registerCleanup(t)
	return b
}

// registerCleanup destroys every object this run created once the suite
// is done with the backend. A vendor's tokens persist between runs, and
// token memory is finite. Only this run's objects are touched.
func (b *conformanceBackend) registerCleanup(t *testing.T) {
	t.Helper()
	// This suite closes the adapter on purpose, so cleanup reopens it. An
	// earlier version logged the closed adapter and left the keys behind.
	t.Cleanup(func() {
		ctx := context.Background()
		adapter := b.adapter
		// A session opened while another token is authenticated cannot see
		// this one's private objects.
		_ = adapter.LogoutToken(ctx)
		if err := adapter.LoginToken(ctx, b.ws, append([]byte(nil), b.userPIN...), b.role); err != nil {
			// One C_Initialize per process.
			adapter.Close()
			fresh, reopenErr := b.reopen()
			if reopenErr != nil {
				t.Logf("conformance cleanup: login failed (%v) and reopening the module failed too: %v", err, reopenErr)
				return
			}
			defer fresh.Close()
			adapter = fresh
			if err := adapter.LoginToken(ctx, b.ws, append([]byte(nil), b.userPIN...), b.role); err != nil {
				t.Logf("conformance cleanup: login through a fresh connection: %v", err)
				return
			}
		}
		defer func() { _ = adapter.LogoutToken(ctx) }()

		s, err := adapter.OpenSession(ctx, b.ws, pk11.SessionOptions{})
		if err != nil {
			t.Logf("conformance cleanup: open session: %v", err)
			return
		}
		defer adapter.CloseSession(ctx, s)

		objs, err := adapter.FindObjects(ctx, s, nil)
		if err != nil {
			t.Logf("conformance cleanup: find objects: %v", err)
			return
		}
		prefix := "conf-" + b.runID + "-"
		for _, o := range objs {
			attrs, err := adapter.GetAttributes(ctx, s, o, []pk11.AttributeType{pk11.AttrLabel})
			if err != nil || len(attrs) == 0 {
				continue
			}
			if !strings.HasPrefix(string(attrs[0].Value), prefix) {
				continue
			}
			if err := adapter.DestroyObject(ctx, s, o); err != nil {
				t.Logf("conformance cleanup: destroy %s: %v", attrs[0].Value, err)
			}
		}
	})
}

// ─── The shared suite ─────────────────────────────────────────────────────

// openLoggedInSession opens a session on the backend's workspace, logs in
// as the backend's role, and registers cleanup.
func (b *conformanceBackend) openLoggedInSession(t *testing.T, opts pk11.SessionOptions) *pk11.Session {
	t.Helper()
	ctx := context.Background()
	s, err := b.adapter.OpenSession(ctx, b.ws, opts)
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	t.Cleanup(func() { _ = b.adapter.CloseSession(context.Background(), s) })

	if err := b.adapter.Login(ctx, s, append([]byte(nil), b.userPIN...), b.role); err != nil {
		t.Fatalf("Login: %v", err)
	}
	return s
}

// runConformanceSuite exercises the full VendorAdapter contract against b.
// Subtests run in declared order, and the last one closes b.adapter.
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

		err = b.adapter.Login(ctx, s, append([]byte(nil), b.wrongPIN...), b.role)
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

		if err := b.adapter.Login(ctx, s, nil, b.role); err != pk11.ErrEmptyPIN {
			t.Fatalf("Login(nil pin) = %v, want ErrEmptyPIN", err)
		}
	})

	// The PIN is zeroed on every return path, including the guard clauses
	// before NewSecurePIN.
	t.Run("Login_ZeroizesCallerPINOnEarlyReturn", func(t *testing.T) {
		s, err := b.adapter.OpenSession(ctx, b.ws, pk11.SessionOptions{})
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		defer b.adapter.CloseSession(ctx, s)

		pin := append([]byte(nil), b.userPIN...)
		cancelled, cancel := context.WithCancel(ctx)
		cancel()

		if err := b.adapter.Login(cancelled, s, pin, b.role); err == nil {
			t.Fatal("Login with a cancelled context succeeded, want an error")
		}
		for i, c := range pin {
			if c != 0 {
				t.Fatalf("caller PIN byte %d = %#x after an early-return Login, want 0", i, c)
			}
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

	// LoginToken_AnchorLifecycle pins LoginToken's edge cases at this layer:
	// an empty PIN, a second login, an idempotent logout. It runs right
	// after "Logout", which leaves the token de-authenticated, and logs
	// the token out again before returning.
	t.Run("LoginToken_AnchorLifecycle", func(t *testing.T) {
		if b.adapter.TokenLoggedIn() {
			t.Fatal("TokenLoggedIn() = true before any LoginToken call")
		}

		if err := b.adapter.LoginToken(ctx, b.ws, nil, b.role); err != pk11.ErrEmptyPIN {
			t.Fatalf("LoginToken(nil pin) = %v, want ErrEmptyPIN", err)
		}
		if b.adapter.TokenLoggedIn() {
			t.Fatal("TokenLoggedIn() = true after a rejected empty-PIN LoginToken")
		}

		if err := b.adapter.LoginToken(ctx, b.ws, append([]byte(nil), b.wrongPIN...), b.role); err == nil {
			t.Fatal("LoginToken with wrong PIN succeeded, want an error")
		}
		if b.adapter.TokenLoggedIn() {
			t.Fatal("TokenLoggedIn() = true after a failed LoginToken")
		}

		if err := b.adapter.LoginToken(ctx, b.ws, append([]byte(nil), b.userPIN...), b.role); err != nil {
			t.Fatalf("LoginToken: %v", err)
		}
		if !b.adapter.TokenLoggedIn() {
			t.Fatal("TokenLoggedIn() = false after a successful LoginToken")
		}

		// A session opened after the anchor login inherits its
		// authentication and can use a CKA_PRIVATE=true key without a login
		// of its own.
		label := b.label("anchor-inherits")
		genSess, err := b.adapter.OpenSession(ctx, b.ws, pk11.SessionOptions{})
		if err != nil {
			t.Fatalf("OpenSession (key gen): %v", err)
		}
		kp, err := b.adapter.GenerateKeyPair(ctx, genSess, pk11.KeyPairRequest{
			Curve: pk11.P256, Label: label, Sign: true, Verify: true,
		})
		if err != nil {
			t.Fatalf("GenerateKeyPair with no session-level login: %v", err)
		}
		_ = b.adapter.CloseSession(ctx, genSess)

		signSess, err := b.adapter.OpenSession(ctx, b.ws, pk11.SessionOptions{})
		if err != nil {
			t.Fatalf("OpenSession (sign): %v", err)
		}
		digest := sha256.Sum256([]byte("anchor login inherited by a fresh session"))
		if _, err := b.adapter.Sign(ctx, signSess, kp.Private, pk11.Mechanism{Type: pk11.MechECDSA}, digest[:]); err != nil {
			t.Fatalf("Sign with no session-level login: %v", err)
		}
		_ = b.adapter.CloseSession(ctx, signSess)

		// A second LoginToken while logged in is an error.
		if err := b.adapter.LoginToken(ctx, b.ws, append([]byte(nil), b.userPIN...), b.role); !errors.Is(err, pk11.ErrTokenAlreadyLoggedIn) {
			t.Fatalf("second LoginToken = %v, want ErrTokenAlreadyLoggedIn", err)
		}
		if !b.adapter.TokenLoggedIn() {
			t.Fatal("TokenLoggedIn() = false after a rejected second LoginToken")
		}

		if err := b.adapter.LogoutToken(ctx); err != nil {
			t.Fatalf("LogoutToken: %v", err)
		}
		if b.adapter.TokenLoggedIn() {
			t.Fatal("TokenLoggedIn() = true after LogoutToken")
		}

		// Idempotent: logging out when not logged in is not an error.
		if err := b.adapter.LogoutToken(ctx); err != nil {
			t.Fatalf("second LogoutToken (idempotent) = %v, want nil", err)
		}

		// The token can be authenticated again after a logout.
		if err := b.adapter.LoginToken(ctx, b.ws, append([]byte(nil), b.userPIN...), b.role); err != nil {
			t.Fatalf("LoginToken after LogoutToken: %v", err)
		}
		if err := b.adapter.LogoutToken(ctx); err != nil {
			t.Fatalf("final LogoutToken: %v", err)
		}
	})

	// Concurrent LoginToken callers cannot both believe they established
	// the anchor.
	t.Run("LoginToken_ConcurrentCallsSerializeToOneWinner", func(t *testing.T) {
		if b.adapter.TokenLoggedIn() {
			t.Fatal("TokenLoggedIn() = true before this subtest")
		}

		const n = 4
		results := make([]error, n)
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				results[i] = b.adapter.LoginToken(ctx, b.ws, append([]byte(nil), b.userPIN...), b.role)
			}(i)
		}
		wg.Wait()

		successes := 0
		for i, err := range results {
			switch {
			case err == nil:
				successes++
			case errors.Is(err, pk11.ErrTokenAlreadyLoggedIn):
				// expected for every loser of the race
			default:
				t.Fatalf("concurrent LoginToken[%d] = %v, want nil or ErrTokenAlreadyLoggedIn", i, err)
			}
		}
		if successes != 1 {
			t.Fatalf("%d of %d concurrent LoginToken calls succeeded, want exactly 1", successes, n)
		}
		if !b.adapter.TokenLoggedIn() {
			t.Fatal("TokenLoggedIn() = false after a concurrent LoginToken race")
		}

		if err := b.adapter.LogoutToken(ctx); err != nil {
			t.Fatalf("LogoutToken: %v", err)
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

		// A real digest of real data.
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

		// The token's raw r||s signature is checked by crypto/ecdsa with the
		// public key read back off the token, so the signature is
		// standards-conformant and not only self-consistent.
		attrs, err := b.adapter.GetAttributes(ctx, s, kp.Public, []pk11.AttributeType{pk11.AttrEcPoint})
		if err != nil {
			t.Fatalf("GetAttributes: %v", err)
		}
		pub, err := pk11.DecodeECPoint(elliptic.P256(), attrs[0].Value)
		if err != nil {
			t.Fatalf("DecodeECPoint: %v", err)
		}
		half := len(sig) / 2
		r := new(big.Int).SetBytes(sig[:half])
		s2 := new(big.Int).SetBytes(sig[half:])
		if !ecdsa.Verify(pub, digest[:], r, s2) {
			t.Fatal("crypto/ecdsa.Verify rejected the HSM-produced signature")
		}

		// A changed digest must fail.
		digest[0] ^= 0xFF
		if err := b.adapter.Verify(ctx, s, kp.Public, pk11.Mechanism{Type: pk11.MechECDSA}, digest[:], sig); err == nil {
			t.Fatal("Verify accepted a signature over a tampered digest")
		}
	})

	t.Run("GenerateKeyPair_PrivateKeyIsSensitiveAndNonExtractable", func(t *testing.T) {
		// A private key can be used through the token and cannot be taken
		// out of it. The token is asked, not the request. CKA_SENSITIVE was
		// once whatever the request's zero value was, and ProtectToolkit
		// 7.3.3 disclosed all 32 bytes to any authenticated session while
		// SoftHSM2 refused.
		s := b.openLoggedInSession(t, pk11.SessionOptions{})
		kp, err := b.adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
			Curve: pk11.P256, Label: b.label("protection"), Sign: true, Verify: true,
		})
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}

		attrs, err := b.adapter.GetAttributes(ctx, s, kp.Private,
			[]pk11.AttributeType{pk11.AttrSensitive, pk11.AttrExtractable})
		if err != nil {
			t.Fatalf("GetAttributes: %v", err)
		}
		got := map[pk11.AttributeType]bool{}
		for _, a := range attrs {
			got[a.Type] = len(a.Value) > 0 && a.Value[0] != 0
		}
		if !got[pk11.AttrSensitive] {
			t.Error("CKA_SENSITIVE is false: PKCS#11 permits the token to reveal this private key in plaintext via C_GetAttributeValue")
		}
		if got[pk11.AttrExtractable] {
			t.Error("CKA_EXTRACTABLE is true: this private key can be wrapped off the token")
		}
	})

	t.Run("GenerateSecretKey_IsSensitive", func(t *testing.T) {
		// The same rule for secret keys, asked of the token. Luna refuses
		// to create a non-sensitive secret key at all; SoftHSM2 and
		// ProtectToolkit-C create one and would disclose CKA_VALUE, so
		// the platform never asks for one.
		s := b.openLoggedInSession(t, pk11.SessionOptions{})
		key, err := b.adapter.GenerateSecretKey(ctx, s, pk11.SecretKeyRequest{
			KeyBits: 256, Label: b.label("secret-protection"), Encrypt: true, Decrypt: true, Extractable: true,
		})
		if err != nil {
			t.Fatalf("GenerateSecretKey: %v", err)
		}
		attrs, err := b.adapter.GetAttributes(ctx, s, key, []pk11.AttributeType{pk11.AttrSensitive})
		if err != nil {
			t.Fatalf("GetAttributes: %v", err)
		}
		if len(attrs) != 1 || len(attrs[0].Value) == 0 || attrs[0].Value[0] == 0 {
			t.Error("CKA_SENSITIVE is false: PKCS#11 permits the token to reveal this secret key in plaintext via C_GetAttributeValue")
		}
	})

	t.Run("FindObjects_ReturnsMoreThanOneBatch", func(t *testing.T) {
		// C_FindObjects is paginated. The loop once stopped after the first
		// batch of 50, so every search returned at most 50 objects with no
		// error. 60 keys under one label is more than one batch.
		const want = 60
		s := b.openLoggedInSession(t, pk11.SessionOptions{})
		label := b.label("batching")
		for i := 0; i < want; i++ {
			if _, err := b.adapter.GenerateSecretKey(ctx, s, pk11.SecretKeyRequest{
				KeyBits: 128, Label: label, Encrypt: true, Decrypt: true,
			}); err != nil {
				t.Fatalf("GenerateSecretKey %d: %v", i, err)
			}
		}

		found, err := b.adapter.FindObjects(ctx, s, []pk11.Attribute{
			{Type: pk11.AttrLabel, Value: []byte(label)},
		})
		if err != nil {
			t.Fatalf("FindObjects: %v", err)
		}
		if len(found) != want {
			t.Fatalf("FindObjects returned %d objects, want %d; the search is truncating", len(found), want)
		}

		for _, o := range found {
			if err := b.adapter.DestroyObject(ctx, s, o); err != nil {
				t.Fatalf("DestroyObject: %v", err)
			}
		}
	})

	t.Run("DestroyObject_RemovesTheObject", func(t *testing.T) {
		// Retiring a key version needs this, and so does cleanup on a token
		// that persists between runs.
		s := b.openLoggedInSession(t, pk11.SessionOptions{})
		label := b.label("destroy-me")
		kp, err := b.adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
			Curve: pk11.P256, Label: label, Sign: true, Verify: true,
		})
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}

		for _, h := range []pk11.ObjectHandle{kp.Private, kp.Public} {
			if err := b.adapter.DestroyObject(ctx, s, h); err != nil {
				t.Fatalf("DestroyObject: %v", err)
			}
		}

		// Asked of the token: the object must be gone.
		found, err := b.adapter.FindObjects(ctx, s, []pk11.Attribute{
			{Type: pk11.AttrLabel, Value: []byte(label)},
		})
		if err != nil {
			t.Fatalf("FindObjects: %v", err)
		}
		if len(found) != 0 {
			t.Fatalf("%d objects still carry label %q after DestroyObject", len(found), label)
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

		tmpl := []pk11.Attribute{
			pk11.NumericAttribute(pk11.AttrClass, uint64(pk11.ClassSecretKey)),
			pk11.NumericAttribute(pk11.AttrKeyType, uint64(pk11.KeyTypeAES)),
			{Type: pk11.AttrLabel, Value: []byte(b.label("payload-key-restored"))},
			{Type: pk11.AttrDecrypt, Value: []byte{1}},
		}
		// AES key wrap carries the key length, yet Luna 7.8.7 refuses the
		// unwrap without CKA_VALUE_LEN, reporting CKR_ATTRIBUTE_TYPE_INVALID
		// (an attribute too many, where one is missing). SoftHSM2 2.6.1
		// refuses the same attribute with CKR_ATTRIBUTE_READ_ONLY, and
		// ProtectToolkit-C takes either. The token's declaration decides.
		if b.caps.UnwrapNeedsValueLen {
			tmpl = append(tmpl, pk11.NumericAttribute(pk11.AttrValueLen, 16))
		}
		unwrapped, err := b.adapter.Unwrap(ctx, s, wrappingKey, mech, wrapped, tmpl)
		if err != nil {
			t.Fatalf("Unwrap with UnwrapNeedsValueLen=%v declared: %v", b.caps.UnwrapNeedsValueLen, err)
		}
		if unwrapped == 0 {
			t.Fatal("Unwrap returned a zero handle")
		}
	})

	// WrapUnwrapDemo_ECPrivateKeyBackupRoundTrip: wrap, destroy, unwrap,
	// sign. It shows the wrap-based backup in
	// docs/key-ceremony-and-recovery.md round-trips. A real backup unwraps
	// onto a different token; C_UnwrapKey does not care which token
	// performs it, so one token proves the mechanism. Extractable: true is
	// the one exception to the platform default, and CKA_SENSITIVE stays
	// true, so C_WrapKey is the only door this key can leave through.
	t.Run("WrapUnwrapDemo_ECPrivateKeyBackupRoundTrip", func(t *testing.T) {
		s := b.openLoggedInSession(t, pk11.SessionOptions{})

		wrappingKey, err := b.adapter.GenerateSecretKey(ctx, s, pk11.SecretKeyRequest{
			KeyBits: 256, Label: b.label("backup-wrap-key"), Wrap: true, Unwrap: true,
		})
		if err != nil {
			t.Fatalf("GenerateSecretKey (wrapping key): %v", err)
		}

		kp, err := b.adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
			Curve: pk11.P256, Label: b.label("backup-target"), Sign: true, Verify: true, Extractable: true,
		})
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}

		// A real digest of real data.
		digest := sha256.Sum256([]byte("wrap-based backup round trip, " + b.name))
		originalSig, err := b.adapter.Sign(ctx, s, kp.Private, pk11.Mechanism{Type: pk11.MechECDSA}, digest[:])
		if err != nil {
			t.Fatalf("Sign (before backup): %v", err)
		}
		if err := b.adapter.Verify(ctx, s, kp.Public, pk11.Mechanism{Type: pk11.MechECDSA}, digest[:], originalSig); err != nil {
			t.Fatalf("Verify (before backup) = %v, want nil", err)
		}

		mech := pk11.Mechanism{Type: pk11.MechAESKeyWrap}
		wrapped, err := b.adapter.Wrap(ctx, s, wrappingKey, kp.Private, mech)
		if b.caps.PrivateKeyWrapRefused != "" {
			var ckr p11.Error
			switch {
			case err == nil:
				t.Fatalf("declared refused (%s), but C_WrapKey wrapped the private key: the declaration is wrong", b.caps.PrivateKeyWrapRefused)
			case !errors.As(err, &ckr) || ckr != p11.CKR_KEY_NOT_WRAPPABLE:
				t.Fatalf("declared refused with CKR_KEY_NOT_WRAPPABLE (%s), got %v", b.caps.PrivateKeyWrapRefused, err)
			}
			t.Skipf("refusal measured as declared: %s", b.caps.PrivateKeyWrapRefused)
		}
		if err != nil {
			t.Fatalf("Wrap: %v", err)
		}
		if len(wrapped) == 0 {
			t.Fatal("Wrap returned empty ciphertext")
		}

		// The original is destroyed. Everything below works from the wrapped
		// backup only.
		if err := b.adapter.DestroyObject(ctx, s, kp.Private); err != nil {
			t.Fatalf("DestroyObject (original private key): %v", err)
		}

		// No CKA_EC_PARAMS in the template. SoftHSM2 2.6.1 rejects an
		// explicit value with CKR_ATTRIBUTE_READ_ONLY; it derives the curve
		// from the wrapped object. The two software backends unwrap without
		// it; Luna never reaches this line, its wrap having been refused.
		restored, err := b.adapter.Unwrap(ctx, s, wrappingKey, mech, wrapped, []pk11.Attribute{
			pk11.NumericAttribute(pk11.AttrClass, uint64(pk11.ClassPrivateKey)),
			pk11.NumericAttribute(pk11.AttrKeyType, uint64(pk11.KeyTypeEC)),
			{Type: pk11.AttrLabel, Value: []byte(b.label("backup-target-restored"))},
			{Type: pk11.AttrSign, Value: []byte{1}},
			{Type: pk11.AttrExtractable, Value: []byte{0}},
		})
		if err != nil {
			t.Fatalf("Unwrap: %v", err)
		}
		if restored == 0 {
			t.Fatal("Unwrap returned a zero handle")
		}

		restoredSig, err := b.adapter.Sign(ctx, s, restored, pk11.Mechanism{Type: pk11.MechECDSA}, digest[:])
		if err != nil {
			t.Fatalf("Sign (after restore): %v", err)
		}
		// Verified against the original public key: the restore produced the
		// same key.
		if err := b.adapter.Verify(ctx, s, kp.Public, pk11.Mechanism{Type: pk11.MechECDSA}, digest[:], restoredSig); err != nil {
			t.Fatalf("Verify (after restore) = %v, want nil; the restored key should produce signatures the original public key still accepts", err)
		}

		// Unwrap is a generic primitive, so this platform cannot force
		// CKA_EXTRACTABLE here the way GenerateKeyPair forces CKA_SENSITIVE.
		// Whether the template's CKA_EXTRACTABLE=false reaches the restored
		// key is the module's declaration, measured here in both
		// directions. A real restore reads this attribute back before
		// trusting the key.
		attrs, err := b.adapter.GetAttributes(ctx, s, restored, []pk11.AttributeType{pk11.AttrExtractable})
		if err != nil {
			t.Fatalf("GetAttributes (restored): %v", err)
		}
		gotExtractable := len(attrs[0].Value) > 0 && attrs[0].Value[0] != 0
		t.Logf("restored private key CKA_EXTRACTABLE=%v (template asked for false); declared UnwrapHonoursExtractable=%v", gotExtractable, b.caps.UnwrapHonoursExtractable)
		if b.caps.UnwrapHonoursExtractable && gotExtractable {
			t.Fatal("declared UnwrapHonoursExtractable, but the restored private key is CKA_EXTRACTABLE=true: the declaration is wrong")
		}
		if !b.caps.UnwrapHonoursExtractable && !gotExtractable {
			t.Fatal("declared that unwrap ignores CKA_EXTRACTABLE, but the restored key honoured it: the declaration is wrong")
		}
	})

	// The remaining declarations, each measured in both directions.

	t.Run("Capability_HandlesSpanSessions", func(t *testing.T) {
		s1 := b.openLoggedInSession(t, pk11.SessionOptions{})
		s2, err := b.adapter.OpenSession(ctx, b.ws, pk11.SessionOptions{})
		if err != nil {
			t.Fatalf("OpenSession (second): %v", err)
		}
		t.Cleanup(func() { _ = b.adapter.CloseSession(context.Background(), s2) })
		kp, err := b.adapter.GenerateKeyPair(ctx, s1, pk11.KeyPairRequest{
			Curve: pk11.P256, Label: b.label("handle-scope"), Sign: true, Verify: true,
		})
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		_, err = b.adapter.GetAttributes(ctx, s2, kp.Public, []pk11.AttributeType{pk11.AttrLabel})
		switch {
		case b.caps.HandlesSpanSessions && err != nil:
			t.Fatalf("declared HandlesSpanSessions, but a handle from one session was refused in another: %v", err)
		case !b.caps.HandlesSpanSessions && err == nil:
			t.Fatal("declared that handles are per session, but a handle from one session was accepted in another: the declaration is wrong")
		case !b.caps.HandlesSpanSessions:
			var ckr p11.Error
			if !errors.As(err, &ckr) || ckr != p11.CKR_OBJECT_HANDLE_INVALID {
				t.Fatalf("handle refused across sessions as declared, but with %v, want CKR_OBJECT_HANDLE_INVALID", err)
			}
		}

		// The same handle after the session it came from is gone.
		if err := b.adapter.CloseSession(ctx, s1); err != nil {
			t.Fatalf("CloseSession (origin): %v", err)
		}
		_, err = b.adapter.GetAttributes(ctx, s2, kp.Public, []pk11.AttributeType{pk11.AttrLabel})
		switch {
		case b.caps.HandlesSurviveSessionClose && err != nil:
			t.Fatalf("declared HandlesSurviveSessionClose, but the handle was refused after its session closed: %v", err)
		case !b.caps.HandlesSurviveSessionClose && err == nil:
			t.Fatal("declared that a handle dies with its session, but it was accepted afterwards: the declaration is wrong")
		}
	})

	t.Run("Capability_ZeroDigest", func(t *testing.T) {
		s := b.openLoggedInSession(t, pk11.SessionOptions{})
		kp, err := b.adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
			Curve: pk11.P256, Label: b.label("zero-digest"), Sign: true, Verify: true,
		})
		if err != nil {
			t.Fatalf("GenerateKeyPair: %v", err)
		}
		// The one place a zero digest is allowed in this suite: it is the
		// subject of the measurement, not a stand-in for data.
		zero := make([]byte, 32)
		var got pk11.ZeroDigestBehaviour
		sig, err := b.adapter.Sign(ctx, s, kp.Private, pk11.Mechanism{Type: pk11.MechECDSA}, zero)
		var ckr p11.Error
		switch {
		case err == nil:
			if verr := b.adapter.Verify(ctx, s, kp.Public, pk11.Mechanism{Type: pk11.MechECDSA}, zero, sig); verr == nil {
				got = pk11.ZeroDigestAccepted
			} else if errors.As(verr, &ckr) && ckr == p11.CKR_SIGNATURE_INVALID {
				got = pk11.ZeroDigestVerifyRefused
			} else {
				t.Fatalf("C_Verify over an all-zero digest failed with %v, which is none of the three measured answers", verr)
			}
		case errors.As(err, &ckr) && ckr == p11.CKR_DATA_INVALID:
			got = pk11.ZeroDigestSignRefused
		default:
			t.Fatalf("C_Sign over an all-zero digest failed with %v, which is none of the three measured answers", err)
		}
		if got != b.caps.ZeroDigest {
			t.Fatalf("declared ZeroDigest=%q, measured %q: the declaration is wrong", b.caps.ZeroDigest, got)
		}
	})

	t.Run("Capability_SecondInitializeInProcess", func(t *testing.T) {
		second, err := pk11.NewAdapterByName(b.adapterName, b.modulePath)
		if err == nil {
			defer second.Close()
		}
		switch {
		case b.caps.SecondInitializeInProcess && err != nil:
			t.Fatalf("declared SecondInitializeInProcess, but a second adapter over the same module failed: %v", err)
		case !b.caps.SecondInitializeInProcess && err == nil:
			t.Fatal("declared that a second C_Initialize is refused, but a second adapter opened: the declaration is wrong")
		case !b.caps.SecondInitializeInProcess:
			var ckr p11.Error
			if !errors.As(err, &ckr) || ckr != p11.CKR_CRYPTOKI_ALREADY_INITIALIZED {
				t.Fatalf("second adapter refused as declared, but with %v, want CKR_CRYPTOKI_ALREADY_INITIALIZED", err)
			}
		}
		if err == nil {
			// The second adapter must see the token too, or it initialized
			// something other than the module the first one holds.
			wss, err := second.Workspaces(ctx)
			if err != nil {
				t.Fatalf("Workspaces through the second adapter: %v", err)
			}
			found := false
			for _, ws := range wss {
				found = found || ws.Serial == b.ws.Serial
			}
			if !found {
				t.Fatalf("the second adapter does not see token %q (serial %s)", b.ws.Label, b.ws.Serial)
			}
		}
	})

	t.Run("Capability_ConcurrentSlotEnumeration", func(t *testing.T) {
		if !b.caps.ConcurrentSlotEnumeration {
			t.Skip("declared serialized: the shared lock serializes Workspaces, so concurrent enumeration is not exercised on this module")
		}
		// Eight callers at once. A module that deadlocks here parks the
		// test until -timeout, which is the evidence.
		var wg sync.WaitGroup
		errs := make(chan error, 8)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, err := b.adapter.Workspaces(ctx)
				errs <- err
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				t.Fatalf("declared ConcurrentSlotEnumeration, but a concurrent Workspaces call failed: %v", err)
			}
		}
	})

	// 200 bits divides to a 25-byte CKA_VALUE_LEN, which a token might
	// accept as a non-standard key. The adapter refuses it first.
	t.Run("GenerateSecretKey_InvalidKeySizeRejected", func(t *testing.T) {
		s := b.openLoggedInSession(t, pk11.SessionOptions{})
		for _, bits := range []int{1, 127, 200, 512, -256} {
			_, err := b.adapter.GenerateSecretKey(ctx, s, pk11.SecretKeyRequest{
				KeyBits: bits, Label: b.label("bad-aes"), Encrypt: true, Decrypt: true,
			})
			if !errors.Is(err, pk11.ErrUnsupportedKeySize) {
				t.Fatalf("GenerateSecretKey(KeyBits=%d) = %v, want ErrUnsupportedKeySize", bits, err)
			}
		}
	})

	// The one concurrency subtest, Capability_ConcurrentSlotEnumeration
	// above, runs only on a module that declares it safe. An earlier
	// version ran unconditionally, eight goroutines calling Workspaces at
	// once, and destabilized the ProtectServer run for the rest of the
	// suite: a later C_OpenSession hung and the suite timed out. That
	// module declares false, keeps the exclusive lock, and skips the
	// measurement with that reason. Anything else added here that runs
	// operations from several goroutines must be tested against
	// ProtectServer with the full suite ahead of it; the deadlock does not
	// reproduce in a fresh process that makes only the one call.

	// AdapterClose must run last. A second Ctx over the same module while
	// this one is live fails with CKR_CRYPTOKI_ALREADY_INITIALIZED, so
	// Close cannot be tested on a disposable instance. t.Cleanup's own
	// Close afterwards is a no-op.
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
