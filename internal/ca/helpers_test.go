package ca_test

// Shared SoftHSM2 test scaffolding for this package's tests. Sub-task 2.2's
// "Decide before starting" entry in docs/phases/phase-2-ca-core.md applies
// to every test file here: SoftHSM2 only. Phase 1's conformance suite
// already proved VendorAdapter generalizes across two independent vendors,
// and the CA layer only ever calls through that interface.

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

func requireSoftHSM2(t *testing.T) string {
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

// newTestAdapter provisions a fresh, isolated SoftHSM2 token and returns a
// ready-to-use adapter, its workspace, and a PIN resolver for it — the
// scaffolding every test in this package needs before it can generate keys
// or build a Signer/CA over them.
func newTestAdapter(t *testing.T) (pk11.VendorAdapter, pk11.Workspace, func() ([]byte, error)) {
	t.Helper()
	modulePath := requireSoftHSM2(t)

	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	confPath := filepath.Join(dir, "softhsm2.conf")
	conf := "directories.tokendir = " + tokenDir + "\n" +
		"objectstore.backend = file\nlog.level = ERROR\n"
	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("SOFTHSM2_CONF", confPath)

	const label, pin = "ca-test-token", "123456"
	cmd := exec.Command("softhsm2-util", "--init-token", "--free",
		"--label", label, "--so-pin", "000000", "--pin", pin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("softhsm2-util --init-token: %v: %s", err, out)
	}

	adapter, err := pk11.NewSoftHSM2Adapter(modulePath)
	if err != nil {
		t.Fatalf("NewSoftHSM2Adapter: %v", err)
	}
	t.Cleanup(func() { adapter.Close() })

	ctx := context.Background()
	wss, err := adapter.Workspaces(ctx)
	if err != nil {
		t.Fatalf("Workspaces: %v", err)
	}
	var ws pk11.Workspace
	for _, w := range wss {
		if w.Label == label {
			ws = w
		}
	}
	if ws.Label == "" {
		t.Fatalf("workspace %q not found among %+v", label, wss)
	}

	resolvePIN := func() ([]byte, error) { return []byte(pin), nil }
	return adapter, ws, resolvePIN
}

// withSession opens a session against ws, logs in, runs fn, and always logs
// out and closes the session — the same lifecycle internal/ca.Signer's own
// unexported withSession follows, duplicated here because tests need to
// drive the adapter directly (e.g. to generate a key before a Signer over
// it exists).
func withSession[T any](t *testing.T, ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, resolvePIN func() ([]byte, error), fn func(*pk11.Session) (T, error)) (T, error) {
	t.Helper()
	var zero T
	s, err := adapter.OpenSession(ctx, ws, pk11.SessionOptions{})
	if err != nil {
		return zero, err
	}
	defer adapter.CloseSession(ctx, s)
	pin, err := resolvePIN()
	if err != nil {
		return zero, err
	}
	if err := adapter.Login(ctx, s, pin, pk11.RoleUser); err != nil {
		return zero, err
	}
	defer adapter.Logout(ctx, s)
	return fn(s)
}
