// Package hsmtest provides the shared backend harness every HSM-touching
// test in this repository runs through.
//
// # Why this is a package and not a _test.go helper
//
// Go cannot share test helpers across packages, so before this existed
// internal/ca and internal/api each carried their own copy of "provision a
// SoftHSM2 token, build an adapter, find the workspace". Two copies is a
// duplication problem; five vendors across two copies is a correctness
// problem, because the copies drift and a vendor added to one is silently
// missing from the other. The registry below is the single place a backend
// is declared, so adding nShield or Luna is one entry plus an adapter —
// not an archaeological survey of every test file.
//
// # The rule this package exists to enforce
//
// Every test that touches a token runs against every backend the
// environment provides (CLAUDE.md §2.4). An abstraction exercised against
// one implementation is a guess, and this repository has the scar to prove
// it: CKA_SENSITIVE was false on every private key it ever generated, and
// the SoftHSM2-only suite stayed green for the whole project because
// SoftHSM2 declines to disclose a key it is permitted to disclose. The
// second backend is what turned that from a latent defect into a fixed one
// (docs/pkcs11-vendor-notes.md).
//
// # Availability, and why a missing backend skips rather than fails
//
// SoftHSM2 needs no hardware and no proprietary SDK, so it is always
// present and carries CI. Every other backend runs only when its
// environment variables are set, and skips otherwise — so a contributor
// with no HSM gets an honest green rather than a red that means nothing,
// and nothing vendor-only is ever reported as CI-verified (CLAUDE.md §2.3).
package hsmtest

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"

	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

// Backend is one vendor's adapter together with the tokens a test needs.
//
// Two tokens are always resolved, because the CA hierarchy this platform
// builds needs two (root and intermediate, on separate tokens — Phase 3b).
// A test that needs only one uses Primary and ignores Secondary.
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
	// to reach this backend: cmd/hsm-pki-keytool takes -module and
	// -adapter, so a test driving the CLI rather than the library needs
	// both to run against anything but the default.
	ModulePath  string
	AdapterName string

	closeOnce sync.Once

	// RunID is folded into every label a run creates by Label.
	//
	// It is not cosmetic. A hardware or emulated vendor's tokens persist
	// between runs, so a fixed label makes the second run of any test
	// collide with the first run's objects — and the ceremony's own
	// "refuses to overwrite an existing key label" guard turns that into a
	// failure. SoftHSM2 gets fresh tokens each run and would not need it;
	// both paths use it anyway so they cannot drift.
	RunID string
}

// Release closes the harness's adapter early.
//
// It exists for tests that hand the same PKCS#11 module to code which opens
// its own connection to it — cmd/hsm-pki-keytool builds an adapter from
// -module, so for the duration of that call there would be two contexts
// over one library. Vendors disagree about whether that is allowed:
// SoftHSM2 2.6.1 tolerates a second C_Initialize through a separate dlopen
// handle, while ProtectToolkit 7.3.3 rejects it with
// CKR_CRYPTOKI_ALREADY_INITIALIZED (docs/pkcs11-vendor-notes.md). Releasing
// first is what makes such a test portable across both.
//
// Safe to call more than once, and safe not to call at all: the backend's
// own cleanup closes the adapter through the same guard.
func (b *Backend) Release() {
	b.closeOnce.Do(func() { b.Adapter.Close() })
}

// Label returns a run-unique object label ending in suffix.
func (b *Backend) Label(suffix string) string {
	return fmt.Sprintf("t-%s-%s", b.RunID, suffix)
}

// PrimaryPINFunc returns a resolver for the primary token's PIN, the shape
// internal/ca's entry points take.
func (b *Backend) PrimaryPINFunc() func() ([]byte, error) {
	return func() ([]byte, error) { return []byte(b.PrimaryPIN), nil }
}

// SecondaryPINFunc returns a resolver for the secondary token's PIN.
func (b *Backend) SecondaryPINFunc() func() ([]byte, error) {
	return func() ([]byte, error) { return []byte(b.SecondaryPIN), nil }
}

// descriptor declares one vendor to the harness.
//
// Adding a backend — nShield and Luna are planned for Phase 7 — means
// adding one of these plus the adapter it constructs. Nothing else in the
// repository's tests should need to change, which is the property this
// indirection is buying.
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
	// Phase 7 adds nShield and Luna here. See docs/test-matrix.md for what
	// a vendor must provide before it can be added.
}

// ForEach runs fn against every backend the environment provides, each as
// its own subtest.
//
// Each subtest builds a fresh backend, and therefore a fresh adapter,
// because a PKCS#11 module permits only one C_Initialize per process: two
// adapters over the same .so alive at once fails
// CKR_CRYPTOKI_ALREADY_INITIALIZED. Subtests run sequentially and each
// adapter is closed by its own cleanup, so only one is ever live.
func ForEach(t *testing.T, fn func(t *testing.T, b *Backend)) {
	t.Helper()
	for _, d := range registry {
		d := d
		t.Run(d.name, func(t *testing.T) {
			fn(t, d.setup(t))
		})
	}
}

// SoftHSM2 builds the SoftHSM2 backend directly, for the few tests that
// need that vendor specifically rather than every configured one — chiefly
// tests that provision an unusual token layout (two tokens sharing a label,
// for instance) which no ordinary Backend would ever hand them.
func SoftHSM2(t *testing.T) *Backend {
	t.Helper()
	return setupSoftHSM2(t)
}

// RequireSoftHSM2 returns the SoftHSM2 module path, skipping when it is
// absent. Exported for the few tests that legitimately need the module path
// itself rather than a Backend.
func RequireSoftHSM2(t *testing.T) string {
	t.Helper()
	modulePath := os.Getenv("SOFTHSM2_MODULE")
	if modulePath == "" {
		modulePath = "/usr/lib/softhsm/libsofthsm2.so"
	}
	if _, err := os.Stat(modulePath); err != nil {
		t.Skip("SoftHSM2 module not found — run inside the dev container (see CONTRIBUTING.md)")
	}
	return modulePath
}

// NewSoftHSM2Tokens provisions n throwaway SoftHSM2 tokens in a temporary
// directory and points SOFTHSM2_CONF at it. It returns the labels and PINs,
// in order.
//
// Exported because a few tests drive token provisioning themselves — the
// ambiguous-label test needs two tokens sharing one label, which no
// Backend would ever hand them.
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
	t.Cleanup(b.Release)
	return b
}

// setupProtectServer wires in the maintainer's own ProtectToolkit tokens.
// Unlike SoftHSM2 it provisions nothing: the user tokens are created once,
// by hand, with ctconf/ctkmu (docs/protectserver-setup.md §3b).
func setupProtectServer(t *testing.T) *Backend {
	t.Helper()
	modulePath := os.Getenv("PROTECTSERVER_MODULE")
	if modulePath == "" {
		t.Skip("PROTECTSERVER_MODULE not set — see docs/protectserver-setup.md; " +
			"this backend is maintainer-verified, never CI-verified (CLAUDE.md §2.3)")
	}
	primaryLabel := os.Getenv("PROTECTSERVER_INTERMEDIATE_WORKSPACE")
	secondaryLabel := os.Getenv("PROTECTSERVER_ROOT_WORKSPACE")
	primaryPIN := os.Getenv("PROTECTSERVER_INTERMEDIATE_PIN")
	secondaryPIN := os.Getenv("PROTECTSERVER_ROOT_PIN")
	if primaryLabel == "" || secondaryLabel == "" || primaryPIN == "" || secondaryPIN == "" {
		t.Skip("ProtectServer needs PROTECTSERVER_INTERMEDIATE_WORKSPACE, " +
			"PROTECTSERVER_ROOT_WORKSPACE, PROTECTSERVER_INTERMEDIATE_PIN and " +
			"PROTECTSERVER_ROOT_PIN — see docs/protectserver-setup.md")
	}
	if primaryLabel == secondaryLabel {
		t.Fatal("PROTECTSERVER_INTERMEDIATE_WORKSPACE and PROTECTSERVER_ROOT_WORKSPACE " +
			"name the same token; the CA hierarchy requires two (phase-3b-pki-hardening.md)")
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
	return b
}

// MustFindWorkspace resolves a token by label and fails the test if it is
// missing or carries no serial number.
//
// The serial check is not incidental: a Workspace built by hand rather than
// returned by Workspaces() has none, and the ceremony's token-identity
// guard compares serials rather than labels (CLAUDE.md §3.8). A backend
// that cannot supply one cannot be used for the two-token tests, and it is
// better to say so here than to fail inside the ceremony.
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
