package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/config"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
)

// writeConfig writes a service configuration for one token of one backend.
// The PIN is read from the MAIN_TEST_PIN variable, as the service does.
func writeConfig(t *testing.T, adapterName, modulePath, label string) string {
	t.Helper()
	body := "pkcs11:\n" +
		"  adapter: \"" + adapterName + "\"\n" +
		"  " + adapterName + ":\n" +
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

func TestVerifyHSMConnection_Success(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		t.Setenv("MAIN_TEST_PIN", b.PrimaryPIN)
		cfg, err := config.Load(writeConfig(t, b.AdapterName, b.ModulePath, b.Primary.Label))
		if err != nil {
			t.Fatalf("config.Load: %v", err)
		}
		b.Release()
		adapter, err := cfg.NewVendorAdapter()
		if err != nil {
			t.Fatalf("NewVendorAdapter: %v", err)
		}
		defer adapter.Close()

		ws, err := verifyHSMConnection(context.Background(), cfg, adapter)
		if err != nil {
			t.Fatalf("verifyHSMConnection: %v", err)
		}
		if ws.Label != b.Primary.Label {
			t.Fatalf("Workspace.Label = %q, want %q", ws.Label, b.Primary.Label)
		}
		if ws.Serial != b.Primary.Serial {
			t.Fatalf("Workspace.Serial = %q, want %q", ws.Serial, b.Primary.Serial)
		}
	})
}

func TestVerifyHSMConnection_UnknownWorkspaceFails(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		t.Setenv("MAIN_TEST_PIN", b.PrimaryPIN)
		cfg, err := config.Load(writeConfig(t, b.AdapterName, b.ModulePath, "no-such-workspace"))
		if err != nil {
			t.Fatalf("config.Load: %v", err)
		}
		b.Release()
		adapter, err := cfg.NewVendorAdapter()
		if err != nil {
			t.Fatalf("NewVendorAdapter: %v", err)
		}
		defer adapter.Close()

		if _, err := verifyHSMConnection(context.Background(), cfg, adapter); err == nil {
			t.Fatal("verifyHSMConnection against an unprovisioned workspace succeeded, want an error")
		}
	})
}

// A wrong PIN counts against the token's failed-login counter on a
// vendor backend. One attempt per run is within what every token allows.
func TestVerifyHSMConnection_WrongPINFails(t *testing.T) {
	hsmtest.ForEach(t, func(t *testing.T, b *hsmtest.Backend) {
		t.Setenv("MAIN_TEST_PIN", "0"+b.PrimaryPIN)
		cfg, err := config.Load(writeConfig(t, b.AdapterName, b.ModulePath, b.Primary.Label))
		if err != nil {
			t.Fatalf("config.Load: %v", err)
		}
		b.Release()
		adapter, err := cfg.NewVendorAdapter()
		if err != nil {
			t.Fatalf("NewVendorAdapter: %v", err)
		}
		defer adapter.Close()

		if _, err := verifyHSMConnection(context.Background(), cfg, adapter); err == nil {
			t.Fatal("verifyHSMConnection with the wrong PIN succeeded, want an error")
		}
	})
}

// TestVerifyHSMConnection_AmbiguousWorkspaceLabelFails provisions two
// tokens with one label. PKCS#11 does not require CKA_LABEL to be unique,
// and the service must refuse to choose between them. This runs on
// SoftHSM2 only: a vendor's tokens are provisioned by hand and no test
// creates a duplicate label there.
func TestVerifyHSMConnection_AmbiguousWorkspaceLabelFails(t *testing.T) {
	modulePath := hsmtest.RequireSoftHSM2(t)
	const label = "main-test-duplicate"
	pins := hsmtest.NewSoftHSM2Tokens(t, label, label)
	t.Setenv("MAIN_TEST_PIN", pins[0])

	cfg, err := config.Load(writeConfig(t, "softhsm2", modulePath, label))
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
	// The operator needs to know which tokens collided. The serial is the
	// field that tells them apart.
	if !strings.Contains(err.Error(), "matches 2 tokens") {
		t.Fatalf("error %q does not say the label was ambiguous", err)
	}
}
