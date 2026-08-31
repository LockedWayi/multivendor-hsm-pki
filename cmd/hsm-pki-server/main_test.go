package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
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
		"  intermediate_key_label: \"ca-intermediate-key-v1\"\n" +
		"  root_cert_path: \"root.pem\"\n" +
		"  root_crl_path: \"root-crl.pem\"\n" +
		"  store_path: \"ca.db\"\n" +
		"  base_url: \"https://pki.example.test\"\n" +
		"  intermediate_cert_path: \"" + filepath.Join(t.TempDir(), "intermediate.pem") + "\"\n"
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

// TestVerifyHSMConnection_AmbiguousWorkspaceLabelFails is CLAUDE.md §3.8 on
// the service side: a label that matches two tokens identifies neither.
//
// PKCS#11 specifies CKA_LABEL as a description and requires no uniqueness,
// so taking the first match means the driver's enumeration order decides
// which token holds the CA's key — and it may decide differently on the next
// boot. cmd/hsm-pki-keytool already refused to choose here; the service used
// to take the first hit, which is the defect this pins.
func TestVerifyHSMConnection_AmbiguousWorkspaceLabelFails(t *testing.T) {
	modulePath := requireSoftHSM2(t)
	const label, pin = "main-test-duplicate", "123456"

	// Two tokens, one label, in a single token directory. SoftHSM2 permits
	// it, which is the whole point: the standard does not forbid it either.
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
	for i := 0; i < 2; i++ {
		cmd := exec.Command("softhsm2-util", "--init-token", "--free",
			"--label", label, "--so-pin", "000000", "--pin", pin)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("softhsm2-util --init-token (%d): %v: %s", i, err, out)
		}
	}
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

	_, err = verifyHSMConnection(context.Background(), cfg, adapter)
	if err == nil {
		t.Fatal("verifyHSMConnection chose between two tokens sharing a label, want a refusal")
	}
	// The error has to be usable: an operator needs to know which tokens
	// collided, and serial is the field that distinguishes them.
	if !strings.Contains(err.Error(), "matches 2 tokens") {
		t.Fatalf("error %q does not say the label was ambiguous", err)
	}
}
