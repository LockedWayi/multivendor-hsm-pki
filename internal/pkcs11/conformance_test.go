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
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
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

	// Login_ZeroizesCallerPINOnEarlyReturn pins the "pin is consumed"
	// contract to every return path, not just the success path. The guard
	// clauses ahead of NewSecurePIN (cancelled context here; an expired
	// session is the other one) used to return with the caller's PIN still
	// readable in the Go heap — the one copy this package can
	// deterministically wipe, left unwiped (CLAUDE.md §3.1).
	t.Run("Login_ZeroizesCallerPINOnEarlyReturn", func(t *testing.T) {
		s, err := b.adapter.OpenSession(ctx, b.ws, pk11.SessionOptions{})
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		defer b.adapter.CloseSession(ctx, s)

		pin := append([]byte(nil), b.userPIN...)
		cancelled, cancel := context.WithCancel(ctx)
		cancel()

		if err := b.adapter.Login(cancelled, s, pin, pk11.RoleUser); err == nil {
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

	// LoginToken_AnchorLifecycle exercises the anchor-login model directly
	// at the pkcs11 layer, not only through internal/ca's CA-level
	// concurrency test. Discovered during Phase 2's final review: every
	// tokenlogin.go function was only ever reached indirectly, through
	// internal/ca/internal/api tests, which showed as 0% coverage on this
	// package's own per-package profile and meant no test here pinned
	// LoginToken's edge cases (a rejected empty PIN, a rejected second
	// login, idempotent logout) at the layer that actually implements them
	// (docs/phases/phase-2-ca-core.md, sub-task 2.8).
	//
	// Runs immediately after "Logout" above, which is the one earlier
	// subtest guaranteed to leave the token de-authenticated — every
	// subtest from here on that calls openLoggedInSession relies on that
	// being true at its start, so this block logs the token back out
	// before returning.
	t.Run("LoginToken_AnchorLifecycle", func(t *testing.T) {
		if b.adapter.TokenLoggedIn() {
			t.Fatal("TokenLoggedIn() = true before any LoginToken call")
		}

		if err := b.adapter.LoginToken(ctx, b.ws, nil, pk11.RoleUser); err != pk11.ErrEmptyPIN {
			t.Fatalf("LoginToken(nil pin) = %v, want ErrEmptyPIN", err)
		}
		if b.adapter.TokenLoggedIn() {
			t.Fatal("TokenLoggedIn() = true after a rejected empty-PIN LoginToken")
		}

		if err := b.adapter.LoginToken(ctx, b.ws, append([]byte(nil), b.wrongPIN...), pk11.RoleUser); err == nil {
			t.Fatal("LoginToken with wrong PIN succeeded, want an error")
		}
		if b.adapter.TokenLoggedIn() {
			t.Fatal("TokenLoggedIn() = true after a failed LoginToken")
		}

		if err := b.adapter.LoginToken(ctx, b.ws, append([]byte(nil), b.userPIN...), pk11.RoleUser); err != nil {
			t.Fatalf("LoginToken: %v", err)
		}
		if !b.adapter.TokenLoggedIn() {
			t.Fatal("TokenLoggedIn() = false after a successful LoginToken")
		}

		// The load-bearing premise sub-task 2.8 was built on: a session
		// opened after the anchor login inherits its authentication and can
		// use a CKA_PRIVATE=true key with no login of its own. Pinned here
		// so a regression fails at this layer, not three layers up in an
		// HTTP concurrency test.
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

		// A second LoginToken while already logged in is an error, not a
		// silent no-op — see LoginToken's doc comment for why silently
		// agreeing would leave two callers disagreeing about who owns the
		// eventual logout.
		if err := b.adapter.LoginToken(ctx, b.ws, append([]byte(nil), b.userPIN...), pk11.RoleUser); !errors.Is(err, pk11.ErrTokenAlreadyLoggedIn) {
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

		// Not a one-shot resource: the token can be re-authenticated after
		// a logout, which is exactly what a long-lived daemon needs across
		// its lifetime even though Phase 2 never re-logs-in on its own.
		if err := b.adapter.LoginToken(ctx, b.ws, append([]byte(nil), b.userPIN...), pk11.RoleUser); err != nil {
			t.Fatalf("LoginToken after LogoutToken: %v", err)
		}
		if err := b.adapter.LogoutToken(ctx); err != nil {
			t.Fatalf("final LogoutToken: %v", err)
		}
	})

	// LoginToken_ConcurrentCallsSerializeToOneWinner exercises loginMu
	// directly: sub-task 2.8's fix is only real if concurrent LoginToken
	// callers cannot both believe they established the anchor. Complements
	// internal/api's TestIssueCertificate_ConcurrentRequests, which proves
	// concurrent signing works once one caller has already logged in, but
	// never exercises concurrent callers racing the login itself.
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
				results[i] = b.adapter.LoginToken(ctx, b.ws, append([]byte(nil), b.userPIN...), pk11.RoleUser)
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

	// GenerateSecretKey_InvalidKeySizeRejected checks the adapter refuses a
	// bad AES key length itself rather than passing bits/8 down and letting
	// each vendor decide. 200 bits is the interesting case: it divides to a
	// 25-byte CKA_VALUE_LEN, which is a plausible-looking value a token
	// might accept as a non-standard key rather than reject.
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

	// No concurrency subtest lives here, and that absence is deliberate.
	//
	// One was written while reviewing base.go's lock discipline: eight
	// goroutines calling Workspaces at once. It exposed two real things and
	// then had to be removed, because it destabilizes the ProtectServer run
	// for the rest of the suite — after that burst, a later C_OpenSession
	// hangs, and the suite times out rather than failing cleanly.
	//
	// What it found is recorded where it belongs instead:
	//   - ProtectToolkit deadlocks inside a concurrently-entered
	//     C_GetSlotList despite CKF_OS_LOCKING_OK. This is why Workspaces
	//     holds the exclusive lock; see its doc comment and
	//     docs/pkcs11-vendor-notes.md.
	//   - PKCS#11 login state is per-token, not per-session, on BOTH
	//     backends, which makes the current open/login/op/logout-per-call
	//     pattern unsafe under concurrent callers. That is a live defect,
	//     tracked as Phase 2 sub-task 2.8, and it is blocked on a
	//     maintainer decision — the test that proves it fixed belongs with
	//     that fix, not ahead of it.
	//
	// Anything added here that runs operations from several goroutines must
	// be tested against ProtectServer with the full suite ahead of it, not
	// in isolation: neither failure reproduces in a freshly started process
	// that only makes the one call.

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
