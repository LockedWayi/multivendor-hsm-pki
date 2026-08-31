package config

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

const validSoftHSM2Config = `
server:
  listen_addr: "0.0.0.0:8080"
pkcs11:
  adapter: "softhsm2"
  session:
    idle_timeout: "5m"
    max_ttl: "1h"
  softhsm2:
    module_path: "/usr/lib/softhsm/libsofthsm2.so"
    workspace_label: "test-token"
    pin_env: "TEST_SOFTHSM2_PIN"
ca:
  curve: "P-256"
  cert_ttl_hours: 8760
  key_label: "ca-signing-key"
  cert_path: "ca-cert.pem"
`

func TestLoad_Success(t *testing.T) {
	t.Setenv("TEST_SOFTHSM2_PIN", "123456")
	path := writeConfig(t, validSoftHSM2Config)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PKCS11.Adapter != AdapterSoftHSM2 {
		t.Fatalf("Adapter = %q, want %q", cfg.PKCS11.Adapter, AdapterSoftHSM2)
	}
	if cfg.PKCS11.SessionOptions.IdleTimeout != 5*time.Minute {
		t.Fatalf("IdleTimeout = %v, want 5m", cfg.PKCS11.SessionOptions.IdleTimeout)
	}
	if cfg.PKCS11.SessionOptions.MaxTTL != time.Hour {
		t.Fatalf("MaxTTL = %v, want 1h", cfg.PKCS11.SessionOptions.MaxTTL)
	}
}

func TestLoad_MissingPINEnvVarFails(t *testing.T) {
	os.Unsetenv("TEST_SOFTHSM2_PIN_UNSET")
	body := `
pkcs11:
  adapter: "softhsm2"
  softhsm2:
    module_path: "/usr/lib/softhsm/libsofthsm2.so"
    workspace_label: "test-token"
    pin_env: "TEST_SOFTHSM2_PIN_UNSET"
`
	path := writeConfig(t, body)

	if _, err := Load(path); err == nil {
		t.Fatal("Load with unset PIN env var succeeded, want an error")
	}
}

func TestLoad_UnknownAdapterFails(t *testing.T) {
	body := `
pkcs11:
  adapter: "quantum-hsm"
`
	path := writeConfig(t, body)

	if _, err := Load(path); err == nil {
		t.Fatal("Load with unknown adapter name succeeded, want an error")
	}
}

func TestLoad_MissingVendorBlockFails(t *testing.T) {
	body := `
pkcs11:
  adapter: "protectserver"
`
	path := writeConfig(t, body)

	if _, err := Load(path); err == nil {
		t.Fatal("Load with adapter=protectserver but no protectserver block succeeded, want an error")
	}
}

func TestLoad_EmptyModulePathFails(t *testing.T) {
	t.Setenv("TEST_PIN", "1234")
	body := `
pkcs11:
  adapter: "softhsm2"
  softhsm2:
    workspace_label: "test-token"
    pin_env: "TEST_PIN"
`
	path := writeConfig(t, body)

	if _, err := Load(path); err == nil {
		t.Fatal("Load with empty module_path succeeded, want an error")
	}
}

func TestLoad_InvalidSessionDurationFails(t *testing.T) {
	t.Setenv("TEST_PIN", "1234")
	body := `
pkcs11:
  adapter: "softhsm2"
  session:
    idle_timeout: "not-a-duration"
  softhsm2:
    module_path: "/usr/lib/softhsm/libsofthsm2.so"
    workspace_label: "test-token"
    pin_env: "TEST_PIN"
`
	path := writeConfig(t, body)

	if _, err := Load(path); err == nil {
		t.Fatal("Load with an invalid idle_timeout succeeded, want an error")
	}
}

func TestLoad_DefaultsAppliedWhenSessionOmitted(t *testing.T) {
	t.Setenv("TEST_PIN", "1234")
	body := `
pkcs11:
  adapter: "softhsm2"
  softhsm2:
    module_path: "/usr/lib/softhsm/libsofthsm2.so"
    workspace_label: "test-token"
    pin_env: "TEST_PIN"
ca:
  curve: "P-256"
  cert_ttl_hours: 8760
  key_label: "ca-signing-key"
  cert_path: "ca-cert.pem"
`
	path := writeConfig(t, body)

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.PKCS11.SessionOptions.IdleTimeout == 0 || cfg.PKCS11.SessionOptions.MaxTTL == 0 {
		t.Fatalf("SessionOptions = %+v, want non-zero defaults", cfg.PKCS11.SessionOptions)
	}
}

func TestLoad_UnknownCurveFails(t *testing.T) {
	t.Setenv("TEST_PIN", "1234")
	body := `
pkcs11:
  adapter: "softhsm2"
  softhsm2:
    module_path: "/usr/lib/softhsm/libsofthsm2.so"
    workspace_label: "test-token"
    pin_env: "TEST_PIN"
ca:
  curve: "P-224"
  cert_ttl_hours: 8760
  key_label: "ca-signing-key"
  cert_path: "ca-cert.pem"
`
	path := writeConfig(t, body)

	if _, err := Load(path); err == nil {
		t.Fatal("Load with an unsupported ca.curve succeeded, want an error")
	}
}

func TestLoad_ZeroCertTTLFails(t *testing.T) {
	t.Setenv("TEST_PIN", "1234")
	body := `
pkcs11:
  adapter: "softhsm2"
  softhsm2:
    module_path: "/usr/lib/softhsm/libsofthsm2.so"
    workspace_label: "test-token"
    pin_env: "TEST_PIN"
ca:
  curve: "P-256"
  cert_ttl_hours: 0
  key_label: "ca-signing-key"
  cert_path: "ca-cert.pem"
`
	path := writeConfig(t, body)

	if _, err := Load(path); err == nil {
		t.Fatal("Load with cert_ttl_hours=0 succeeded, want an error")
	}
}

func TestLoad_EmptyKeyLabelFails(t *testing.T) {
	t.Setenv("TEST_PIN", "1234")
	body := `
pkcs11:
  adapter: "softhsm2"
  softhsm2:
    module_path: "/usr/lib/softhsm/libsofthsm2.so"
    workspace_label: "test-token"
    pin_env: "TEST_PIN"
ca:
  curve: "P-256"
  cert_ttl_hours: 8760
  cert_path: "ca-cert.pem"
`
	path := writeConfig(t, body)

	if _, err := Load(path); err == nil {
		t.Fatal("Load with an empty ca.key_label succeeded, want an error")
	}
}

func TestLoad_EmptyCertPathFails(t *testing.T) {
	t.Setenv("TEST_PIN", "1234")
	body := `
pkcs11:
  adapter: "softhsm2"
  softhsm2:
    module_path: "/usr/lib/softhsm/libsofthsm2.so"
    workspace_label: "test-token"
    pin_env: "TEST_PIN"
ca:
  curve: "P-256"
  cert_ttl_hours: 8760
  key_label: "ca-signing-key"
`
	path := writeConfig(t, body)

	if _, err := Load(path); err == nil {
		t.Fatal("Load with an empty ca.cert_path succeeded, want an error")
	}
}

func TestCAConfig_Curve(t *testing.T) {
	t.Setenv("TEST_SOFTHSM2_PIN", "123456")
	cfg, err := Load(writeConfig(t, validSoftHSM2Config))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := cfg.CA.Curve(); got != pkcs11.P256 {
		t.Fatalf("CA.Curve() = %v, want P256", got)
	}
}

func TestLoad_MissingFileFails(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml")); err == nil {
		t.Fatal("Load of a missing file succeeded, want an error")
	}
}

func TestResolvePIN(t *testing.T) {
	t.Setenv("TEST_SOFTHSM2_PIN", "123456")
	path := writeConfig(t, validSoftHSM2Config)
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	pin, err := cfg.ResolvePIN()
	if err != nil {
		t.Fatalf("ResolvePIN: %v", err)
	}
	if string(pin) != "123456" {
		t.Fatalf("ResolvePIN = %q, want %q", pin, "123456")
	}
}

func TestNewVendorAdapter_UnknownAdapterFails(t *testing.T) {
	// Load rejects an unknown adapter before NewVendorAdapter would ever see
	// one, so this exercises PKCS11Config.selectedVendor directly through a
	// Config value constructed by hand rather than via Load.
	cfg := &Config{PKCS11: PKCS11Config{Adapter: "quantum-hsm"}}
	if _, err := cfg.NewVendorAdapter(); err == nil {
		t.Fatal("NewVendorAdapter with an unknown adapter name succeeded, want an error")
	}
}
