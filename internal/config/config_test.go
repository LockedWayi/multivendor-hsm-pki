package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
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
  intermediate_key_label: "ca-intermediate-key-v1"
  intermediate_cert_path: "intermediate.pem"
  root_cert_path: "root.pem"
  root_crl_path: "root-crl.pem"
  store_path: "ca.db"
  base_url: "https://pki.example.test"
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
  intermediate_key_label: "ca-intermediate-key-v1"
  intermediate_cert_path: "intermediate.pem"
  root_cert_path: "root.pem"
  root_crl_path: "root-crl.pem"
  store_path: "ca.db"
  base_url: "https://pki.example.test"
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
  intermediate_key_label: "ca-intermediate-key-v1"
  intermediate_cert_path: "intermediate.pem"
  root_cert_path: "root.pem"
  root_crl_path: "root-crl.pem"
  store_path: "ca.db"
  base_url: "https://pki.example.test"
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
  intermediate_key_label: "ca-intermediate-key-v1"
  intermediate_cert_path: "intermediate.pem"
  root_cert_path: "root.pem"
  root_crl_path: "root-crl.pem"
  store_path: "ca.db"
  base_url: "https://pki.example.test"
`
	path := writeConfig(t, body)

	if _, err := Load(path); err == nil {
		t.Fatal("Load with cert_ttl_hours=0 succeeded, want an error")
	}
}

// TestLoad_RequiredCAFieldsRejectEmpty pins that every ca.* path and label
// is required rather than defaulted. The service no longer creates a CA when
// it finds none (internal/ca.LoadIntermediate), so an unset field is a
// misconfiguration to report at startup — and a default would silently point
// the service at a location the operator never chose.
func TestLoad_RequiredCAFieldsRejectEmpty(t *testing.T) {
	fields := []string{
		"intermediate_key_label",
		"intermediate_cert_path",
		"root_cert_path",
		"root_crl_path",
		"store_path",
		"base_url",
	}
	all := map[string]string{
		"intermediate_key_label": `"ca-intermediate-key-v1"`,
		"intermediate_cert_path": `"intermediate.pem"`,
		"root_cert_path":         `"root.pem"`,
		"root_crl_path":          `"root-crl.pem"`,
		"store_path":             `"ca.db"`,
		"base_url":               `"https://pki.example.test"`,
	}

	for _, omitted := range fields {
		t.Run("missing "+omitted, func(t *testing.T) {
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
`
			for name, value := range all {
				if name == omitted {
					continue
				}
				body += "  " + name + ": " + value + "\n"
			}
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Fatalf("Load without ca.%s succeeded, want an error", omitted)
			}
		})
	}
}

// TestConfig_NoRootKeyReferences is sub-task 3b.2's "grep-verifiable"
// requirement made executable.
//
// The security property is that a compromise of the running service cannot
// reach the root key, and the structural reason it holds is that the
// service's configuration has no way to name the root's token, workspace, or
// key label — so the process never authenticates that token at all.
//
// A future field could erode that quietly, which is what this guards. Note
// the distinction it encodes: RootCertPath and RootCRLPath are permitted,
// because a certificate and a CRL are public artifacts that confer no
// ability to use a key. A root_key_label or root_workspace_label would not
// be, and neither would a second PIN environment variable for the root's
// token.
func TestConfig_NoRootKeyReferences(t *testing.T) {
	forbidden := []string{
		"root_key_label",
		"root_key",
		"root_workspace",
		"root_workspace_label",
		"root_token",
		"root_slot",
		"root_pin",
		"root_pin_env",
	}

	caType := reflect.TypeOf(CAConfig{})
	pkcs11Type := reflect.TypeOf(PKCS11Config{})
	vendorType := reflect.TypeOf(VendorConfig{})

	for _, typ := range []reflect.Type{caType, pkcs11Type, vendorType} {
		for i := 0; i < typ.NumField(); i++ {
			tag := typ.Field(i).Tag.Get("yaml")
			name, _, _ := strings.Cut(tag, ",")
			for _, bad := range forbidden {
				if name == bad {
					t.Fatalf("%s carries a %q field: the service's configuration must never be able to name the root's token or key (docs/phases/phase-3b-pki-hardening.md)",
						typ.Name(), name)
				}
			}
		}
	}

	// The two root fields that ARE allowed must still be exactly the public
	// artifacts, so that a rename cannot smuggle something else past the
	// list above.
	allowedRootFields := map[string]bool{"root_cert_path": true, "root_crl_path": true}
	for i := 0; i < caType.NumField(); i++ {
		name, _, _ := strings.Cut(caType.Field(i).Tag.Get("yaml"), ",")
		if strings.HasPrefix(name, "root_") && !allowedRootFields[name] {
			t.Fatalf("CAConfig has an unexpected root-tier field %q; only public artifacts (%v) may be referenced", name, allowedRootFields)
		}
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

// TestLoad_RejectsUnusableBaseURL pins that ca.base_url is validated as what
// it becomes — the stem of a URL embedded in every issued certificate —
// rather than merely being non-empty.
//
// The cost of accepting a bad one is asymmetric: startup succeeds, issuance
// succeeds, and the defect surfaces only when a relying party tries to fetch
// a CRL months later. By then the only fix is re-issuing every certificate
// signed in the meantime, because an extension cannot be edited after the
// signature.
func TestLoad_RejectsUnusableBaseURL(t *testing.T) {
	for _, tc := range []struct{ name, value string }{
		{"unfetchable scheme", "ldap://pki.example.test"},
		{"no scheme at all", "pki.example.test"},
		{"no host", "https://"},
		{"carries a query string", "https://pki.example.test/?v=1"},
		{"carries a fragment", "https://pki.example.test/#ca"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEST_SOFTHSM2_PIN", "123456")
			body := strings.Replace(validSoftHSM2Config,
				`base_url: "https://pki.example.test"`,
				`base_url: "`+tc.value+`"`, 1)
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Fatalf("Load with ca.base_url %q succeeded, want an error", tc.value)
			}
		})
	}
}

// TestLoad_AcceptsBaseURLWithPathPrefix covers the deployment that is not a
// bare origin: a CA served under a path on a shared host. The prefix has to
// survive, because internal/api.LeafDistributionFor appends the route paths
// to whatever this holds.
func TestLoad_AcceptsBaseURLWithPathPrefix(t *testing.T) {
	t.Setenv("TEST_SOFTHSM2_PIN", "123456")
	body := strings.Replace(validSoftHSM2Config,
		`base_url: "https://pki.example.test"`,
		`base_url: "https://shared.example.test/pki/"`, 1)

	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CA.BaseURL != "https://shared.example.test/pki/" {
		t.Fatalf("BaseURL = %q, want the configured value unchanged", cfg.CA.BaseURL)
	}
}

// TestLoad_RejectsEmptyPINEnvVar covers the difference between "set" and
// "usable". os.LookupEnv reports true for PIN="", so without this the
// service passes startup validation and fails later, at an HSM login,
// further from the cause than it needs to be.
func TestLoad_RejectsEmptyPINEnvVar(t *testing.T) {
	t.Setenv("TEST_SOFTHSM2_PIN", "")
	if _, err := Load(writeConfig(t, validSoftHSM2Config)); err == nil {
		t.Fatal("Load with an empty PIN environment variable succeeded, want an error")
	}
}

// TestLoad_RejectsNegativeCRLNumberFloor pins RFC 5280 §5.2.3: a CRL number
// is a non-negative integer. big.Int parses "-1" happily, and the value is
// only consumed when a rebuilt store seeds its counter — the one moment
// this field exists for, and the worst moment to discover a typo.
func TestLoad_RejectsNegativeCRLNumberFloor(t *testing.T) {
	t.Setenv("TEST_SOFTHSM2_PIN", "123456")
	body := validSoftHSM2Config + "  crl_number_floor: \"-1\"\n"
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("Load with a negative ca.crl_number_floor succeeded, want an error")
	}
}

// TestLoad_RejectsNonPositiveSessionBudgets covers durations that parse but
// cannot describe a usable session: a budget of zero or less is not a
// shorter budget, it is one that is already exceeded when the session opens.
func TestLoad_RejectsNonPositiveSessionBudgets(t *testing.T) {
	for _, tc := range []struct{ name, field, value string }{
		{"negative idle_timeout", "idle_timeout", "-5m"},
		{"zero idle_timeout", "idle_timeout", "0s"},
		{"negative max_ttl", "max_ttl", "-1h"},
		{"zero max_ttl", "max_ttl", "0s"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("TEST_SOFTHSM2_PIN", "123456")
			body := strings.Replace(validSoftHSM2Config,
				"    idle_timeout: \"5m\"\n    max_ttl: \"1h\"\n",
				"    "+tc.field+": \""+tc.value+"\"\n", 1)
			if _, err := Load(writeConfig(t, body)); err == nil {
				t.Fatalf("Load with %s=%s succeeded, want an error", tc.field, tc.value)
			}
		})
	}
}
