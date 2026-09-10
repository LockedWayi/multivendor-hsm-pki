package pkcs11_test

// TestConformance is the cross-vendor suite: every subtest runs, unchanged,
// against every backend the environment provides. SoftHSM2 is always
// present in the dev container and carries CI. ProtectServer runs when
// PROTECTSERVER_MODULE is set and skips otherwise.
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
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

const (
	softhsm2SOPIN    = "000000"
	softhsm2UserPIN  = "123456"
	softhsm2WrongPIN = "000001"

	protectServerDefaultWorkspace = "hsm-pki-dev"
	protectServerWrongPIN         = "0000"
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
	runID    string
	// reopen builds a second connection to the same module, for the case
	// where cleanup cannot use the first one. See registerCleanup.
	reopen func() (pk11.VendorAdapter, error)
}

func (b *conformanceBackend) label(suffix string) string {
	return fmt.Sprintf("conf-%s-%s", b.runID, suffix)
}

// conformanceBackends is this suite's own vendor list, separate from
// internal/hsmtest's registry. This suite needs a wrong PIN and tolerance
// for the adapter being closed part-way through, which the shared harness
// does not provide. TestConformanceCoversEveryRegisteredVendor keeps the
// two lists equal.
var conformanceBackends = []struct {
	name  string
	setup func(t *testing.T) *conformanceBackend
}{
	{"SoftHSM2", setupSoftHSM2Backend},
	{"ProtectServer", setupProtectServerBackend},
}

// TestConformanceCoversEveryRegisteredVendor fails when a vendor is in
// internal/hsmtest's registry and not in this suite. Without it the new
// vendor would run in every suite except the one that finds vendor
// divergence. Names and order are compared.
func TestConformanceCoversEveryRegisteredVendor(t *testing.T) {
	var covered []string
	for _, be := range conformanceBackends {
		covered = append(covered, be.name)
	}
	registered := hsmtest.Vendors()
	if !slices.Equal(covered, registered) {
		t.Fatalf("conformance suite covers %v but internal/hsmtest registers %v.\n"+
			"Adding a vendor means an entry in BOTH lists until they are unified "+
			"(docs/test-matrix.md, backlog item 9). A vendor missing here runs "+
			"everywhere except the suite that exists to find its divergence.",
			covered, registered)
	}
}

// TestConformance runs the full suite against every available backend.
func TestConformance(t *testing.T) {
	for _, be := range conformanceBackends {
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
			"; run inside the dev container (see CONTRIBUTING.md)")
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
	// SOFTHSM2_CONF is process-wide. The backends run sequentially.
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

	b := &conformanceBackend{
		name:     "SoftHSM2",
		adapter:  adapter,
		ws:       ws,
		userPIN:  []byte(softhsm2UserPIN),
		wrongPIN: []byte(softhsm2WrongPIN),
		runID:    runID,
		reopen:   func() (pk11.VendorAdapter, error) { return pk11.NewSoftHSM2Adapter(modulePath) },
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
		if err := adapter.LoginToken(ctx, b.ws, append([]byte(nil), b.userPIN...), pk11.RoleUser); err != nil {
			// One C_Initialize per process.
			adapter.Close()
			fresh, reopenErr := b.reopen()
			if reopenErr != nil {
				t.Logf("conformance cleanup: login failed (%v) and reopening the module failed too: %v", err, reopenErr)
				return
			}
			defer fresh.Close()
			adapter = fresh
			if err := adapter.LoginToken(ctx, b.ws, append([]byte(nil), b.userPIN...), pk11.RoleUser); err != nil {
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

// ─── ProtectServer backend setup ─────────────────────────────────────────

func setupProtectServerBackend(t *testing.T) *conformanceBackend {
	t.Helper()
	modulePath := os.Getenv("PROTECTSERVER_MODULE")
	if modulePath == "" {
		t.Skip("PROTECTSERVER_MODULE not set " +
			"(this backend cannot run in public CI: proprietary SDK)")
	}

	label := os.Getenv("PROTECTSERVER_WORKSPACE")
	if label == "" {
		label = protectServerDefaultWorkspace
	}
	pin := os.Getenv("PROTECTSERVER_PIN")
	if pin == "" {
		t.Fatal("PROTECTSERVER_MODULE is set but PROTECTSERVER_PIN is not")
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

	b := &conformanceBackend{
		name:     "ProtectServer",
		adapter:  adapter,
		ws:       ws,
		userPIN:  []byte(pin),
		wrongPIN: []byte(protectServerWrongPIN),
		runID:    fmt.Sprintf("%d", time.Now().UnixNano()),
		reopen:   func() (pk11.VendorAdapter, error) { return pk11.NewProtectServerAdapter(modulePath) },
	}
	b.registerCleanup(t)
	return b
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

	// LoginToken_AnchorLifecycle pins LoginToken's edge cases at this layer:
	// an empty PIN, a second login, an idempotent logout. It runs right
	// after "Logout", which leaves the token de-authenticated, and logs
	// the token out again before returning.
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

		// The token can be authenticated again after a logout.
		if err := b.adapter.LoginToken(ctx, b.ws, append([]byte(nil), b.userPIN...), pk11.RoleUser); err != nil {
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
			KeyBits: 256, Label: b.label("backup-wrap-key"), Wrap: true, Unwrap: true, Sensitive: true,
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
		// from the wrapped object. Both backends unwrap without it.
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
		// SoftHSM2 2.6.1 honours the template's CKA_EXTRACTABLE=false.
		// ProtectToolkit 7.3.3 does not: the restored key comes back
		// extractable. A real restore reads this attribute back before
		// trusting the key.
		attrs, err := b.adapter.GetAttributes(ctx, s, restored, []pk11.AttributeType{pk11.AttrExtractable})
		if err != nil {
			t.Fatalf("GetAttributes (restored): %v", err)
		}
		gotExtractable := len(attrs[0].Value) > 0 && attrs[0].Value[0] != 0
		t.Logf("restored private key CKA_EXTRACTABLE=%v (template asked for false)", gotExtractable)
		if b.name == "SoftHSM2" && gotExtractable {
			t.Fatal("SoftHSM2 restored private key is CKA_EXTRACTABLE=true, contradicting the unwrap template; this backend was previously observed honoring it")
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

	// There is no concurrency subtest here. One was written, eight
	// goroutines calling Workspaces at once, and it destabilized the
	// ProtectServer run for the rest of the suite: a later C_OpenSession
	// hung and the suite timed out. What it found is recorded on
	// Workspaces in base.go. Anything added here that runs operations from
	// several goroutines must be tested against ProtectServer with the full
	// suite ahead of it; the deadlock does not reproduce in a fresh process
	// that makes only the one call.

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
