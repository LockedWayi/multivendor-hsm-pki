package api_test

// Sub-task 2.4's tests, like the rest of Phase 2, run against SoftHSM2 only
// — see the "Decide before starting" entry in docs/phases/phase-2-ca-core.md.

import (
	"context"
	"crypto/x509/pkix"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/ca"
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

// newTestCA provisions a fresh SoftHSM2 token and bootstraps a CA over it.
func newTestCA(t *testing.T) *ca.CA {
	t.Helper()
	modulePath := requireSoftHSM2(t)

	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	confPath := filepath.Join(dir, "softhsm2.conf")
	conf := "directories.tokendir = " + tokenDir + "\nobjectstore.backend = file\nlog.level = ERROR\n"
	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("SOFTHSM2_CONF", confPath)

	const label, pin = "api-test-token", "123456"
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

	c, err := ca.Bootstrap(ctx, adapter, ws, pk11.SessionOptions{}, resolvePIN, ca.BootstrapParams{
		KeyLabel:     "api-test-ca-key",
		CertPath:     filepath.Join(dir, "ca-cert.pem"),
		Curve:        pk11.P256,
		Subject:      pkix.Name{CommonName: "hsm-pki-platform api test CA"},
		RootValidity: 24 * time.Hour,
		CertTTL:      time.Hour,
	})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	return c
}
