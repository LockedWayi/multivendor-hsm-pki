// Package hsmtest is the backend harness every token-touching test runs
// through. Go cannot share test helpers across packages, so the registry
// below is the one place a backend is declared: the two-token shape every
// suite uses and the single-token shape the conformance suite uses are
// two setups on one entry. Adding a vendor is an adapter and one entry.
//
// Every test that touches a token runs against every backend the
// environment provides. One backend cannot find a class of defect:
// CKA_SENSITIVE was false on every private key this platform generated,
// and the SoftHSM2-only suite stayed green because SoftHSM2 declines to
// disclose a key it is permitted to disclose.
//
// SoftHSM2 needs no hardware and no SDK, so it is always present and
// carries CI. Every other backend skips when its <VENDOR>_MODULE variable
// is unset. With the module set and another of its variables missing, the
// setup fails rather than skips: a half-configured backend is a
// configuration error, not an absent backend, and a run that quietly
// dropped a vendor is the run this harness exists to prevent. Nothing
// vendor-only is reported as CI-verified.
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
	return pk11.NewAdapterByName(name, modulePath)
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
// same module to code which opens its own connection. Every backend
// measured so far answers a second C_Initialize in one process with
// CKR_CRYPTOKI_ALREADY_INITIALIZED (Capabilities.SecondInitializeInProcess,
// asserted by the conformance suite), so the first adapter has to go
// before the second can open. Safe to call more than once.
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
// one of these and the adapter it constructs.
type descriptor struct {
	name string
	// setup returns a live Backend, or calls t.Skip when the environment
	// does not provide this vendor.
	setup func(t *testing.T) *Backend
	// single returns the one-token shape the conformance suite runs on,
	// with a wrong PIN and a chosen role, or calls t.Skip as setup does.
	single func(t *testing.T) *Single
}

// registry is the list every ForEach walks, in order.
var registry = []descriptor{
	{"SoftHSM2", setupSoftHSM2, singleSoftHSM2},
	{"ProtectServer", setupProtectServer, singleProtectServer},
	{"Luna", setupLuna, singleLuna},
	// nShield is added here when it is run. docs/test-matrix.md says what
	// a vendor must provide first.
}

// Vendors returns the registry's backend names, in order.
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
		AdapterName:  pk11.AdapterSoftHSM2,
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
		t.Fatal("PROTECTSERVER_MODULE is set but PROTECTSERVER_INTERMEDIATE_WORKSPACE, " +
			"PROTECTSERVER_ROOT_WORKSPACE, PROTECTSERVER_INTERMEDIATE_PIN or " +
			"PROTECTSERVER_ROOT_PIN is not")
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
		AdapterName:  pk11.AdapterProtectServer,
		RunID:        runID(),
	}
	t.Cleanup(b.Release)
	t.Cleanup(func() { b.Cleanup(t) })
	return b
}

// setupLuna uses two partitions on the maintainer's own Luna Network HSM,
// assigned to this client and initialized by hand. It provisions nothing.
// Every login here is the Crypto Officer (CKU_USER): the code under test
// logs in as CKU_USER itself, so a different role in the harness would
// mix two identities in one test. The conformance suite is where the
// other Luna roles are measured.
func setupLuna(t *testing.T) *Backend {
	t.Helper()
	modulePath := os.Getenv("LUNA_MODULE")
	if modulePath == "" {
		t.Skip("LUNA_MODULE not set: " +
			"this backend is maintainer-verified, never CI-verified")
	}
	// The module reads its client configuration (appliance, certificates)
	// from this variable at load time. Without it the module loads and
	// finds no partitions, which would read as a missing token.
	if os.Getenv("ChrystokiConfigurationPath") == "" {
		t.Fatal("LUNA_MODULE is set but ChrystokiConfigurationPath is not")
	}
	primaryLabel := os.Getenv("LUNA_INTERMEDIATE_WORKSPACE")
	secondaryLabel := os.Getenv("LUNA_ROOT_WORKSPACE")
	primaryPIN := os.Getenv("LUNA_INTERMEDIATE_PIN")
	secondaryPIN := os.Getenv("LUNA_ROOT_PIN")
	if primaryLabel == "" || secondaryLabel == "" || primaryPIN == "" || secondaryPIN == "" {
		t.Fatal("LUNA_MODULE is set but LUNA_INTERMEDIATE_WORKSPACE, LUNA_ROOT_WORKSPACE, " +
			"LUNA_INTERMEDIATE_PIN or LUNA_ROOT_PIN is not")
	}
	if primaryLabel == secondaryLabel {
		t.Fatal("LUNA_INTERMEDIATE_WORKSPACE and LUNA_ROOT_WORKSPACE " +
			"name the same partition; the CA hierarchy requires two")
	}

	adapter, err := pk11.NewLunaAdapter(modulePath)
	if err != nil {
		t.Fatalf("NewLunaAdapter: %v", err)
	}
	b := &Backend{
		Name:         "Luna",
		Adapter:      adapter,
		Primary:      MustFindWorkspace(t, adapter, primaryLabel),
		Secondary:    MustFindWorkspace(t, adapter, secondaryLabel),
		PrimaryPIN:   primaryPIN,
		SecondaryPIN: secondaryPIN,
		ModulePath:   modulePath,
		AdapterName:  pk11.AdapterLuna,
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

// Single is one vendor's single token, the shape the conformance suite in
// internal/pkcs11 runs on: one workspace, its PIN, a PIN that is wrong for
// it, and the role every login uses. It carries what a test needs to open
// a second connection to the same module, because that suite closes the
// adapter on purpose and its cleanup has to get back in.
type Single struct {
	Name      string
	Adapter   pk11.VendorAdapter
	Workspace pk11.Workspace
	PIN       []byte
	// WrongPIN fails as a wrong PIN and not as a length error: Luna
	// enforces a minimum of 8, so it is at least that long everywhere.
	WrongPIN []byte
	// Role is the login identity. Role's zero value is CKU_SO, so it is
	// set explicitly for every backend.
	Role        pk11.Role
	ModulePath  string
	AdapterName string
	// RunID is folded into every object label the suite creates.
	RunID string
}

// Reopen builds a second connection to the same module.
func (s *Single) Reopen() (pk11.VendorAdapter, error) {
	return pk11.NewAdapterByName(s.AdapterName, s.ModulePath)
}

// ForEachSingle runs fn against every backend the environment provides,
// each as its own subtest, in the single-token shape. The skip rule is
// ForEach's.
func ForEachSingle(t *testing.T, fn func(t *testing.T, s *Single)) {
	t.Helper()
	for _, d := range registry {
		d := d
		t.Run(d.name, func(t *testing.T) {
			fn(t, d.single(t))
		})
	}
}

// singleSoftHSM2 provisions a throwaway token. The wrong PIN is chosen
// against the PIN NewSoftHSM2Tokens hands out.
func singleSoftHSM2(t *testing.T) *Single {
	t.Helper()
	modulePath := RequireSoftHSM2(t)
	id := runID()
	label := "conformance-" + id
	pins := NewSoftHSM2Tokens(t, label)
	adapter, err := pk11.NewSoftHSM2Adapter(modulePath)
	if err != nil {
		t.Fatalf("NewSoftHSM2Adapter: %v", err)
	}
	t.Cleanup(func() { adapter.Close() })
	wrong := "00000000"
	if wrong == pins[0] {
		wrong = "00000001"
	}
	return &Single{
		Name: "SoftHSM2", Adapter: adapter, Workspace: MustFindWorkspace(t, adapter, label),
		PIN: []byte(pins[0]), WrongPIN: []byte(wrong), Role: pk11.RoleUser,
		ModulePath: modulePath, AdapterName: pk11.AdapterSoftHSM2, RunID: id,
	}
}

// singleProtectServer uses the maintainer's emulator token named by
// PROTECTSERVER_WORKSPACE, which the whole-suite command in the test
// matrix sets alongside the two-token variables.
func singleProtectServer(t *testing.T) *Single {
	t.Helper()
	modulePath := os.Getenv("PROTECTSERVER_MODULE")
	if modulePath == "" {
		t.Skip("PROTECTSERVER_MODULE not set: " +
			"this backend is maintainer-verified, never CI-verified")
	}
	label := os.Getenv("PROTECTSERVER_WORKSPACE")
	pin := os.Getenv("PROTECTSERVER_PIN")
	if label == "" || pin == "" {
		t.Fatal("PROTECTSERVER_MODULE is set but PROTECTSERVER_WORKSPACE or PROTECTSERVER_PIN is not")
	}
	adapter, err := pk11.NewProtectServerAdapter(modulePath)
	if err != nil {
		t.Fatalf("NewProtectServerAdapter: %v", err)
	}
	t.Cleanup(func() { adapter.Close() })
	return &Single{
		Name: "ProtectServer", Adapter: adapter, Workspace: MustFindWorkspace(t, adapter, label),
		PIN: []byte(pin), WrongPIN: []byte("00000000"), Role: pk11.RoleUser,
		ModulePath: modulePath, AdapterName: pk11.AdapterProtectServer, RunID: runID(),
	}
}

// singleLuna uses the partition LUNA_WORKSPACE names. LUNA_ROLE picks the
// identity the whole conformance suite logs in as: co (the Crypto
// Officer, CKU_USER, the default), lco (the Limited Crypto Officer) or cu
// (the Crypto User). Running the suite once per role is how a restricted
// role's refusals are measured rather than assumed.
func singleLuna(t *testing.T) *Single {
	t.Helper()
	modulePath := os.Getenv("LUNA_MODULE")
	if modulePath == "" {
		t.Skip("LUNA_MODULE not set: " +
			"this backend is maintainer-verified, never CI-verified")
	}
	if os.Getenv("ChrystokiConfigurationPath") == "" {
		t.Fatal("LUNA_MODULE is set but ChrystokiConfigurationPath is not")
	}
	label := os.Getenv("LUNA_WORKSPACE")
	pin := os.Getenv("LUNA_PIN")
	if label == "" || pin == "" {
		t.Fatal("LUNA_MODULE is set but LUNA_WORKSPACE or LUNA_PIN is not")
	}
	role, err := lunaRole(os.Getenv("LUNA_ROLE"))
	if err != nil {
		t.Fatal(err)
	}
	adapter, err := pk11.NewLunaAdapter(modulePath)
	if err != nil {
		t.Fatalf("NewLunaAdapter: %v", err)
	}
	t.Cleanup(func() { adapter.Close() })
	return &Single{
		Name: "Luna", Adapter: adapter, Workspace: MustFindWorkspace(t, adapter, label),
		PIN: []byte(pin), WrongPIN: []byte("00000000"), Role: role,
		ModulePath: modulePath, AdapterName: pk11.AdapterLuna, RunID: runID(),
	}
}

// lunaRole maps LUNA_ROLE to a login identity. An unknown value fails
// rather than falling back: a run that silently used another role would
// report the wrong role's behaviour.
func lunaRole(v string) (pk11.Role, error) {
	switch v {
	case "", "co":
		return pk11.RoleUser, nil
	case "lco":
		return pk11.LunaRoleLimitedCryptoOfficer, nil
	case "cu":
		return pk11.LunaRoleCryptoUser, nil
	default:
		return 0, fmt.Errorf("LUNA_ROLE=%q: want co, lco or cu", v)
	}
}
