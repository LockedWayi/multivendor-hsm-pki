package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/LockedWayi/hsm-pki-platform/internal/config"
)

// requireSoftHSM2 skips the test when no SoftHSM2 module is present, the
// same convention internal/pkcs11's conformance suite uses — this test
// exercises real adapter calls, not just config parsing, so it needs an
// actual PKCS#11 module.
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

func writeSoftHSM2Config(t *testing.T, modulePath, label string) string {
	t.Helper()
	body := "pkcs11:\n" +
		"  adapter: \"softhsm2\"\n" +
		"  softhsm2:\n" +
		"    module_path: \"" + modulePath + "\"\n" +
		"    workspace_label: \"" + label + "\"\n" +
		"    pin_env: \"MAIN_TEST_PIN\"\n" +
		"ca:\n" +
		"  curve: \"P-256\"\n" +
		"  cert_ttl_hours: 8760\n" +
		"  key_label: \"ca-signing-key\"\n" +
		"  cert_path: \"" + filepath.Join(t.TempDir(), "ca-cert.pem") + "\"\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func provisionToken(t *testing.T, label, pin string) {
	t.Helper()
	dir := t.TempDir()
	tokenDir := filepath.Join(dir, "tokens")
	if err := os.MkdirAll(tokenDir, 0700); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	confPath := filepath.Join(dir, "softhsm2.conf")
	conf := "directories.tokendir = " + tokenDir + "\n" +
		"objectstore.backend = file\n" +
		"log.level = ERROR\n"
	if err := os.WriteFile(confPath, []byte(conf), 0600); err != nil {
		t.Fatalf("WriteFile(softhsm2.conf): %v", err)
	}
	t.Setenv("SOFTHSM2_CONF", confPath)

	cmd := exec.Command("softhsm2-util", "--init-token", "--free",
		"--label", label, "--so-pin", "000000", "--pin", pin)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("softhsm2-util --init-token: %v: %s", err, out)
	}
}

func TestVerifyHSMConnection_Success(t *testing.T) {
	modulePath := requireSoftHSM2(t)
	const label, pin = "main-test-ok", "123456"
	provisionToken(t, label, pin)
	t.Setenv("MAIN_TEST_PIN", pin)

	cfg, err := config.Load(writeSoftHSM2Config(t, modulePath, label))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	adapter, err := cfg.NewVendorAdapter()
	if err != nil {
		t.Fatalf("NewVendorAdapter: %v", err)
	}
	defer adapter.Close()

	ws, err := verifyHSMConnection(context.Background(), cfg, adapter)
	if err != nil {
		t.Fatalf("verifyHSMConnection: %v", err)
	}
	if ws.Label != label {
		t.Fatalf("Workspace.Label = %q, want %q", ws.Label, label)
	}
}

func TestVerifyHSMConnection_UnknownWorkspaceFails(t *testing.T) {
	modulePath := requireSoftHSM2(t)
	const realLabel, pin = "main-test-realtoken", "123456"
	provisionToken(t, realLabel, pin)
	t.Setenv("MAIN_TEST_PIN", pin)

	// Config points at a workspace label that was never provisioned.
	cfg, err := config.Load(writeSoftHSM2Config(t, modulePath, "no-such-workspace"))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	adapter, err := cfg.NewVendorAdapter()
	if err != nil {
		t.Fatalf("NewVendorAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := verifyHSMConnection(context.Background(), cfg, adapter); err == nil {
		t.Fatal("verifyHSMConnection against an unprovisioned workspace succeeded, want an error")
	}
}

func TestVerifyHSMConnection_WrongPINFails(t *testing.T) {
	modulePath := requireSoftHSM2(t)
	const label, realPIN = "main-test-wrongpin", "123456"
	provisionToken(t, label, realPIN)
	t.Setenv("MAIN_TEST_PIN", "000001")

	cfg, err := config.Load(writeSoftHSM2Config(t, modulePath, label))
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	adapter, err := cfg.NewVendorAdapter()
	if err != nil {
		t.Fatalf("NewVendorAdapter: %v", err)
	}
	defer adapter.Close()

	if _, err := verifyHSMConnection(context.Background(), cfg, adapter); err == nil {
		t.Fatal("verifyHSMConnection with the wrong PIN succeeded, want an error")
	}
}
