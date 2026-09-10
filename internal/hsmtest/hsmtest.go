// Package hsmtest is the backend harness every token-touching test runs
// through. Go cannot share test helpers across packages, so the registry
// below is the one place a backend is declared. Adding a vendor is one
// entry plus an adapter.
//
// Every test that touches a token runs against every backend the
// environment provides. One backend cannot find a class of defect:
// CKA_SENSITIVE was false on every private key this platform generated,
// and the SoftHSM2-only suite stayed green because SoftHSM2 declines to
// disclose a key it is permitted to disclose.
//
// SoftHSM2 needs no hardware and no SDK, so it is always present and
// carries CI. Every other backend runs when its environment variables are
// set, and skips otherwise. Nothing vendor-only is reported as CI-verified.
package hsmtest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// Backend is one vendor's adapter together with the two tokens a test
// needs. The CA hierarchy needs two tokens, root and intermediate. A
// single-token test uses Primary.
type Backend struct {
	// Name is the vendor's name as it appears in subtest output.
	Name string
	// Adapter is live and closed by the test's own cleanup.
	Adapter pk11.VendorAdapter
	// Primary is the token a single-token test works on, and the one that
	// holds the intermediate in a two-token test.
	Primary pk11.Workspace
	// Secondary holds the root in a two-token test.
	Secondary pk11.Workspace

	PrimaryPIN   string
	SecondaryPIN string

	// ModulePath and AdapterName are what a command-line entry point needs
	// to reach this backend.
	ModulePath  string
	AdapterName string

	closeOnce  sync.Once
	releaseMu  sync.Mutex
	isReleased bool

	// RunID is folded into every label Label creates. A vendor's tokens
	// persist between runs, so a fixed label would collide with the
	// previous run's objects.
	RunID string
}

// labelPrefix is what every label from Label starts with, and what cleanup
// matches on.
func (b *Backend) labelPrefix() string { return "t-" + b.RunID + "-" }

// Cleanup destroys every object this run created on both tokens. The
// harness registers it. It destroys only objects whose label carries this
// run's id; litter from earlier runs belongs to the operator
// (ci/token-cleanup). Failures are logged, not fatal.
func (b *Backend) Cleanup(t *testing.T) {
	t.Helper()

	// The harness adapter is tried first. It may be closed: internal/api
	// closes it on purpose in two tests, without calling Release. An
	// earlier version then logged the failure and left the keys on the
	// token, so this retries with a fresh connection.
	if !b.released() {
		if err := b.destroyAllRunObjects(b.Adapter); err == nil {
			return
		} else {
			t.Logf("hsmtest: %s cleanup through the harness adapter failed (%v); retrying with a fresh connection", b.Name, err)
			// One C_Initialize per process; ProtectToolkit rejects a second.
			b.Release()
		}
	}

	fresh, err := newAdapterByName(b.AdapterName, b.ModulePath)
	if err != nil {
		t.Logf("hsmtest: reopening %s for cleanup: %v", b.Name, err)
		return
	}
	defer fresh.Close()
	if err := b.destroyAllRunObjects(fresh); err != nil {
		t.Logf("hsmtest: cleaning up %s objects: %v", b.Name, err)
	}
}

// destroyAllRunObjects removes this run's objects from both tokens,
// stopping at the first token that fails.
func (b *Backend) destroyAllRunObjects(adapter pk11.VendorAdapter) error {
	for _, ws := range []pk11.Workspace{b.Primary, b.Secondary} {
		if err := b.destroyRunObjects(adapter, ws); err != nil {
			return fmt.Errorf("token %q: %w", ws.Label, err)
		}
	}
	return nil
}

func newAdapterByName(name, modulePath string) (pk11.VendorAdapter, error) {
	switch name {
	case "protectserver":
		return pk11.NewProtectServerAdapter(modulePath)
	default:
		return pk11.NewSoftHSM2Adapter(modulePath)
	}
}

// destroyRunObjects lists every object on the token and destroys the ones
// carrying this run's prefix. PKCS#11 has no prefix search.
func (b *Backend) destroyRunObjects(adapter pk11.VendorAdapter, ws pk11.Workspace) error {
	ctx := context.Background()

	// PKCS#11 authenticates a token for the whole application, and a
	// session on token B while the application is logged into token A
	// cannot see B's private objects. An earlier version skipped the login
	// when anything was authenticated and silently removed only the public
	// halves.
	pin := b.PrimaryPIN
	if ws.Serial == b.Secondary.Serial {
		pin = b.SecondaryPIN
	}
	_ = adapter.LogoutToken(ctx)
	if err := adapter.LoginToken(ctx, ws, []byte(pin), pk11.RoleUser); err != nil {
		return fmt.Errorf("login: %w", err)
	}
	defer func() { _ = adapter.LogoutToken(ctx) }()

	s, err := adapter.OpenSession(ctx, ws, pk11.SessionOptions{})
	if err != nil {
		return fmt.Errorf("open session: %w", err)
	}
	defer adapter.CloseSession(ctx, s)

	objs, err := adapter.FindObjects(ctx, s, nil)
	if err != nil {
		return fmt.Errorf("find objects: %w", err)
	}
	prefix := b.labelPrefix()
	for _, o := range objs {
		attrs, err := adapter.GetAttributes(ctx, s, o, []pk11.AttributeType{pk11.AttrLabel})
		if err != nil || len(attrs) == 0 {
			continue
		}
		if !strings.HasPrefix(string(attrs[0].Value), prefix) {
			continue
		}
		if err := adapter.DestroyObject(ctx, s, o); err != nil {
			return fmt.Errorf("destroy %s: %w", attrs[0].Value, err)
		}
	}
	return nil
}

func (b *Backend) released() bool {
	b.releaseMu.Lock()
	defer b.releaseMu.Unlock()
	return b.isReleased
}

// Release closes the harness's adapter early, for tests that hand the
// same module to code which opens its own connection. SoftHSM2 2.6.1
// tolerates a second C_Initialize through a separate dlopen handle;
// ProtectToolkit 7.3.3 rejects it with CKR_CRYPTOKI_ALREADY_INITIALIZED.
// Safe to call more than once.
func (b *Backend) Release() {
	b.closeOnce.Do(func() {
		b.releaseMu.Lock()
		b.isReleased = true
		b.releaseMu.Unlock()
		b.Adapter.Close()
	})
}

// Label returns a run-unique object label ending in suffix.
func (b *Backend) Label(suffix string) string {
	return fmt.Sprintf("t-%s-%s", b.RunID, suffix)
}

// PrimaryPINFunc returns a resolver for the primary token's PIN, the shape
// internal/ca takes.
func (b *Backend) PrimaryPINFunc() func() ([]byte, error) {
	return func() ([]byte, error) { return []byte(b.PrimaryPIN), nil }
}

// SecondaryPINFunc returns a resolver for the secondary token's PIN.
func (b *Backend) SecondaryPINFunc() func() ([]byte, error) {
	return func() ([]byte, error) { return []byte(b.SecondaryPIN), nil }
}

// descriptor declares one vendor to the harness. Adding a backend means
// one of these plus the adapter it constructs.
type descriptor struct {
	name string
	// setup returns a live Backend, or calls t.Skip when the environment
	// does not provide this vendor.
	setup func(t *testing.T) *Backend
}

// registry is the list every ForEach walks, in order.
var registry = []descriptor{
	{"SoftHSM2", setupSoftHSM2},
	{"ProtectServer", setupProtectServer},
	// nShield and Luna are added here when they are run. docs/test-matrix.md
	// says what a vendor must provide first.
}

// Vendors returns the registry's backend names, in order. The conformance
// suite in internal/pkcs11 keeps its own backend list, because it needs a
// shape this harness does not provide (a wrong PIN, and tolerance for the
// adapter being closed mid-suite). A test compares the two lists, so a
// vendor added to one and not the other fails instead of running in every
// suite except the one that finds vendor divergence.
func Vendors() []string {
	names := make([]string, len(registry))
	for i, d := range registry {
		names[i] = d.name
	}
	return names
}

// ForEach runs fn against every backend the environment provides, each as
// its own subtest. Each subtest builds a fresh adapter: a module permits
// one C_Initialize per process, so two adapters over one module fail with
// CKR_CRYPTOKI_ALREADY_INITIALIZED. Subtests run sequentially.
func ForEach(t *testing.T, fn func(t *testing.T, b *Backend)) {
	t.Helper()
	for _, d := range registry {
		d := d
		t.Run(d.name, func(t *testing.T) {
			fn(t, d.setup(t))
		})
	}
}

// SoftHSM2 builds the SoftHSM2 backend directly, for tests that need a
// token layout no vendor backend provides.
func SoftHSM2(t *testing.T) *Backend {
	t.Helper()
	return setupSoftHSM2(t)
}

// RequireSoftHSM2 returns the SoftHSM2 module path, skipping when it is
// absent.
func RequireSoftHSM2(t *testing.T) string {
	t.Helper()
	modulePath := os.Getenv("SOFTHSM2_MODULE")
	if modulePath == "" {
		modulePath = "/usr/lib/softhsm/libsofthsm2.so"
	}
	if _, err := os.Stat(modulePath); err != nil {
		t.Skip("SoftHSM2 module not found; run inside the dev container (see CONTRIBUTING.md)")
	}
	return modulePath
}

// NewSoftHSM2Tokens provisions throwaway SoftHSM2 tokens with the given
// labels in a temporary directory, points SOFTHSM2_CONF at it, and returns
// the PINs in order. Exported for the tests that need two tokens sharing
// one label.
func NewSoftHSM2Tokens(t *testing.T, labels ...string) (pins []string) {
	t.Helper()
	RequireSoftHSM2(t)

	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	confPath := filepath.Join(dir, "softhsm2.conf")
	conf := "directories.tokendir = " + tokenDir + "\nobjectstore.backend = file\nlog.level = ERROR\n"
	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		t.Fatalf("WriteFile(softhsm2.conf): %v", err)
	}
	t.Setenv("SOFTHSM2_CONF", confPath)

	for i, label := range labels {
		pin := fmt.Sprintf("%06d", 111111*(i+1))
		cmd := exec.Command("softhsm2-util", "--init-token", "--free",
			"--label", label, "--so-pin", "000000", "--pin", pin)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("softhsm2-util --init-token (%s): %v: %s", label, err, out)
		}
		pins = append(pins, pin)
	}
	return pins
}

func setupSoftHSM2(t *testing.T) *Backend {
	t.Helper()
	modulePath := RequireSoftHSM2(t)

	const primaryLabel, secondaryLabel = "hsmtest-primary", "hsmtest-secondary"
	pins := NewSoftHSM2Tokens(t, primaryLabel, secondaryLabel)

	adapter, err := pk11.NewSoftHSM2Adapter(modulePath)
	if err != nil {
		t.Fatalf("NewSoftHSM2Adapter: %v", err)
	}
	b := &Backend{
		Name:         "SoftHSM2",
		Adapter:      adapter,
		Primary:      MustFindWorkspace(t, adapter, primaryLabel),
		Secondary:    MustFindWorkspace(t, adapter, secondaryLabel),
		PrimaryPIN:   pins[0],
		SecondaryPIN: pins[1],
		ModulePath:   modulePath,
		AdapterName:  "softhsm2",
		RunID:        runID(),
	}
	// Cleanups run last in, first out: Cleanup needs a live adapter, so
	// Release is registered first.
	t.Cleanup(b.Release)
	t.Cleanup(func() { b.Cleanup(t) })
	return b
}

// setupProtectServer uses the maintainer's own ProtectToolkit-C software
// emulation tokens. It provisions nothing: the tokens are created once,
// by hand, with ctconf and ctkmu.
func setupProtectServer(t *testing.T) *Backend {
	t.Helper()
	modulePath := os.Getenv("PROTECTSERVER_MODULE")
	if modulePath == "" {
		t.Skip("PROTECTSERVER_MODULE not set: " +
			"this backend is maintainer-verified, never CI-verified")
	}
	primaryLabel := os.Getenv("PROTECTSERVER_INTERMEDIATE_WORKSPACE")
	secondaryLabel := os.Getenv("PROTECTSERVER_ROOT_WORKSPACE")
	primaryPIN := os.Getenv("PROTECTSERVER_INTERMEDIATE_PIN")
	secondaryPIN := os.Getenv("PROTECTSERVER_ROOT_PIN")
	if primaryLabel == "" || secondaryLabel == "" || primaryPIN == "" || secondaryPIN == "" {
		t.Skip("ProtectServer needs PROTECTSERVER_INTERMEDIATE_WORKSPACE, " +
			"PROTECTSERVER_ROOT_WORKSPACE, PROTECTSERVER_INTERMEDIATE_PIN and " +
			"PROTECTSERVER_ROOT_PIN")
	}
	if primaryLabel == secondaryLabel {
		t.Fatal("PROTECTSERVER_INTERMEDIATE_WORKSPACE and PROTECTSERVER_ROOT_WORKSPACE " +
			"name the same token; the CA hierarchy requires two")
	}

	adapter, err := pk11.NewProtectServerAdapter(modulePath)
	if err != nil {
		t.Fatalf("NewProtectServerAdapter: %v", err)
	}
	b := &Backend{
		Name:         "ProtectServer",
		Adapter:      adapter,
		Primary:      MustFindWorkspace(t, adapter, primaryLabel),
		Secondary:    MustFindWorkspace(t, adapter, secondaryLabel),
		PrimaryPIN:   primaryPIN,
		SecondaryPIN: secondaryPIN,
		ModulePath:   modulePath,
		AdapterName:  "protectserver",
		RunID:        runID(),
	}
	t.Cleanup(b.Release)
	t.Cleanup(func() { b.Cleanup(t) })
	return b
}

// MustFindWorkspace resolves a token by label and fails the test if it is
// missing or carries no serial. The ceremony compares serials, so a
// backend that reports none cannot run the two-token tests.
func MustFindWorkspace(t *testing.T, adapter pk11.VendorAdapter, label string) pk11.Workspace {
	t.Helper()
	wss, err := adapter.Workspaces(context.Background())
	if err != nil {
		t.Fatalf("Workspaces: %v", err)
	}
	for _, w := range wss {
		if w.Label == label {
			if w.Serial == "" {
				t.Fatalf("workspace %q carries no token serial; the token-identity check needs one", label)
			}
			return w
		}
	}
	t.Fatalf("workspace %q not found among %+v", label, wss)
	return pk11.Workspace{}
}

func runID() string { return fmt.Sprintf("%d", time.Now().UnixNano()) }
