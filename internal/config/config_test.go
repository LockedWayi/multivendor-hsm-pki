package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
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

// TestLoad_RequiredCAFieldsRejectEmpty: every ca.* path and label is
// required, not defaulted.
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

// TestConfig_NoRootKeyReferences: the service's configuration has no way
// to name the root's token, workspace or key label, so the process never
// authenticates that token. RootCertPath and RootCRLPath are permitted:
// a certificate and a CRL confer no ability to use a key.
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
	serverType := reflect.TypeOf(ServerConfig{})
	tlsType := reflect.TypeOf(TLSConfig{})
	apiType := reflect.TypeOf(APIConfig{})

	for _, typ := range []reflect.Type{caType, pkcs11Type, vendorType, serverType, tlsType, apiType} {
		for i := 0; i < typ.NumField(); i++ {
			tag := typ.Field(i).Tag.Get("yaml")
			name, _, _ := strings.Cut(tag, ",")
			for _, bad := range forbidden {
				if name == bad {
					t.Fatalf("%s carries a %q field: the service's configuration must never be able to name the root's token or key",
						typ.Name(), name)
				}
			}
		}
	}

	// The two allowed root fields must be exactly the public artifacts.
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
	// Load rejects an unknown adapter first, so selectedVendor is exercised
	// through a hand-built Config.
	cfg := &Config{PKCS11: PKCS11Config{Adapter: "quantum-hsm"}}
	if _, err := cfg.NewVendorAdapter(); err == nil {
		t.Fatal("NewVendorAdapter with an unknown adapter name succeeded, want an error")
	}
}

// TestLoad_RejectsUnusableBaseURL: ca.base_url becomes the stem of a URL
// in every issued certificate, and a bad one is found by a relying party
// months later.
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

// TestLoad_AcceptsBaseURLWithPathPrefix: a CA served under a path keeps
// its prefix.
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

// TestLoad_RejectsEmptyPINEnvVar: os.LookupEnv reports true for PIN="".
func TestLoad_RejectsEmptyPINEnvVar(t *testing.T) {
	t.Setenv("TEST_SOFTHSM2_PIN", "")
	if _, err := Load(writeConfig(t, validSoftHSM2Config)); err == nil {
		t.Fatal("Load with an empty PIN environment variable succeeded, want an error")
	}
}

// TestLoad_RejectsNegativeCRLNumberFloor: RFC 5280 §5.2.3 CRL numbers are
// non-negative, and big.Int parses "-1".
func TestLoad_RejectsNegativeCRLNumberFloor(t *testing.T) {
	t.Setenv("TEST_SOFTHSM2_PIN", "123456")
	body := validSoftHSM2Config + "  crl_number_floor: \"-1\"\n"
	if _, err := Load(writeConfig(t, body)); err == nil {
		t.Fatal("Load with a negative ca.crl_number_floor succeeded, want an error")
	}
}

// TestLoad_RejectsNonPositiveSessionBudgets: a budget of zero or less is
// already exceeded when the session opens.
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

func TestLoad_AuthenticatedSurface(t *testing.T) {
	t.Setenv("TEST_SOFTHSM2_PIN", "123456")
	// The tls block is nested under server, which validSoftHSM2Config
	// opens at the top of the document; yaml needs it under that key.
	body := `
server:
  listen_addr: "0.0.0.0:8080"
  tls:
    listen_addr: "0.0.0.0:8443"
    key_label: "ca-tls-key-v1"
    cert_path: "tls.pem"
api:
  issuers:
    "urn:hsm-pki:operator:alice":
      profiles: [tls-server, tls-client]
      names: ["dns:*.example.test", "cn:*.example.test", "uri:urn:hsm-pki:operator:*"]
  revokers: ["urn:hsm-pki:operator:alice", "urn:hsm-pki:operator:bob"]
` + validSoftHSM2Config[len("\nserver:\n  listen_addr: \"0.0.0.0:8080\"\n"):]
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.TLS == nil {
		t.Fatal("Server.TLS is nil after loading a tls block")
	}
	if cfg.Server.TLS.ListenAddr != "0.0.0.0:8443" || cfg.Server.TLS.KeyLabel != "ca-tls-key-v1" || cfg.Server.TLS.CertPath != "tls.pem" {
		t.Fatalf("Server.TLS = %+v", *cfg.Server.TLS)
	}
	if len(cfg.API.Issuers) != 1 || len(cfg.API.Revokers) != 2 {
		t.Fatalf("API = %+v, want one issuer and two revokers", cfg.API)
	}
	if got := cfg.API.Entitlements.Identities(); len(got) != 1 || got[0] != "urn:hsm-pki:operator:alice" {
		t.Fatalf("Entitlements.Identities() = %v", got)
	}
}

func TestLoad_WithoutTLSTheWriteEndpointsAreUnreachable(t *testing.T) {
	t.Setenv("TEST_SOFTHSM2_PIN", "123456")
	cfg, err := Load(writeConfig(t, validSoftHSM2Config))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Server.TLS != nil {
		t.Fatalf("Server.TLS = %+v, want nil when no tls block is present", *cfg.Server.TLS)
	}
	if len(cfg.API.Issuers) != 0 || len(cfg.API.Revokers) != 0 || len(cfg.API.Entitlements) != 0 {
		t.Fatalf("API = %+v, want nothing configured", cfg.API)
	}
}

// TestLoad_AuthenticatedSurfaceRefusals: the tls and api blocks are
// checked together, and every half-configuration is refused.
func TestLoad_AuthenticatedSurfaceRefusals(t *testing.T) {
	t.Setenv("TEST_SOFTHSM2_PIN", "123456")
	base := validSoftHSM2Config[len("\nserver:\n  listen_addr: \"0.0.0.0:8080\"\n"):]
	for _, tc := range []struct {
		name, server, api, want string
	}{
		{
			"api lists without a tls listener",
			"server:\n  listen_addr: \"0.0.0.0:8080\"\n",
			"api:\n  issuers:\n    \"urn:a\": {profiles: [tls-client], names: [\"cn:*\"]}\n",
			"server.tls is not",
		},
		{
			"tls without issuers",
			"server:\n  listen_addr: \"0.0.0.0:8080\"\n  tls:\n    listen_addr: \"0.0.0.0:8443\"\n    key_label: \"ca-tls-key-v1\"\n    cert_path: \"tls.pem\"\n",
			"api:\n  revokers: [\"urn:a\"]\n",
			"api.issuers is empty",
		},
		{
			"tls without revokers",
			"server:\n  listen_addr: \"0.0.0.0:8080\"\n  tls:\n    listen_addr: \"0.0.0.0:8443\"\n    key_label: \"ca-tls-key-v1\"\n    cert_path: \"tls.pem\"\n",
			"api:\n  issuers:\n    \"urn:a\": {profiles: [tls-client], names: [\"cn:*\"]}\n",
			"api.revokers is empty",
		},
		{
			"tls missing its key label",
			"server:\n  listen_addr: \"0.0.0.0:8080\"\n  tls:\n    listen_addr: \"0.0.0.0:8443\"\n    cert_path: \"tls.pem\"\n",
			"api:\n  issuers:\n    \"urn:a\": {profiles: [tls-client], names: [\"cn:*\"]}\n  revokers: [\"urn:a\"]\n",
			"server.tls.key_label is empty",
		},
		{
			"tls on the public listener's address",
			"server:\n  listen_addr: \"0.0.0.0:8080\"\n  tls:\n    listen_addr: \"0.0.0.0:8080\"\n    key_label: \"ca-tls-key-v1\"\n    cert_path: \"tls.pem\"\n",
			"api:\n  issuers:\n    \"urn:a\": {profiles: [tls-client], names: [\"cn:*\"]}\n  revokers: [\"urn:a\"]\n",
			"same as server.listen_addr",
		},
		{
			"the intermediate's key as the TLS key",
			"server:\n  listen_addr: \"0.0.0.0:8080\"\n  tls:\n    listen_addr: \"0.0.0.0:8443\"\n    key_label: \"ca-intermediate-key-v1\"\n    cert_path: \"tls.pem\"\n",
			"api:\n  issuers:\n    \"urn:a\": {profiles: [tls-client], names: [\"cn:*\"]}\n  revokers: [\"urn:a\"]\n",
			"is the intermediate's key label",
		},
		{
			"a revoker listed twice",
			"server:\n  listen_addr: \"0.0.0.0:8080\"\n  tls:\n    listen_addr: \"0.0.0.0:8443\"\n    key_label: \"ca-tls-key-v1\"\n    cert_path: \"tls.pem\"\n",
			"api:\n  issuers:\n    \"urn:a\": {profiles: [tls-client], names: [\"cn:*\"]}\n  revokers: [\"urn:a\", \"urn:a\"]\n",
			"lists \"urn:a\" twice",
		},
		{
			"an empty revoker identity",
			"server:\n  listen_addr: \"0.0.0.0:8080\"\n  tls:\n    listen_addr: \"0.0.0.0:8443\"\n    key_label: \"ca-tls-key-v1\"\n    cert_path: \"tls.pem\"\n",
			"api:\n  issuers:\n    \"urn:a\": {profiles: [tls-client], names: [\"cn:*\"]}\n  revokers: [\"\"]\n",
			"contains an empty identity",
		},
		{
			"the old list form of issuers",
			"server:\n  listen_addr: \"0.0.0.0:8080\"\n  tls:\n    listen_addr: \"0.0.0.0:8443\"\n    key_label: \"ca-tls-key-v1\"\n    cert_path: \"tls.pem\"\n",
			"api:\n  issuers: [\"urn:a\"]\n  revokers: [\"urn:a\"]\n",
			"parsing",
		},
		{
			"an issuer granted nothing",
			"server:\n  listen_addr: \"0.0.0.0:8080\"\n  tls:\n    listen_addr: \"0.0.0.0:8443\"\n    key_label: \"ca-tls-key-v1\"\n    cert_path: \"tls.pem\"\n",
			"api:\n  issuers:\n    \"urn:a\": {profiles: [], names: [\"cn:*\"]}\n  revokers: [\"urn:a\"]\n",
			"lists no profile",
		},
		{
			"an issuer granted a profile that does not exist",
			"server:\n  listen_addr: \"0.0.0.0:8080\"\n  tls:\n    listen_addr: \"0.0.0.0:8443\"\n    key_label: \"ca-tls-key-v1\"\n    cert_path: \"tls.pem\"\n",
			"api:\n  issuers:\n    \"urn:a\": {profiles: [tls-clinet], names: [\"cn:*\"]}\n  revokers: [\"urn:a\"]\n",
			"which ca.profiles does not define",
		},
		{
			"an issuer granted the internal-only profile",
			"server:\n  listen_addr: \"0.0.0.0:8080\"\n  tls:\n    listen_addr: \"0.0.0.0:8443\"\n    key_label: \"ca-tls-key-v1\"\n    cert_path: \"tls.pem\"\n",
			"api:\n  issuers:\n    \"urn:a\": {profiles: [ocsp-responder], names: [\"cn:*\"]}\n  revokers: [\"urn:a\"]\n",
			"no client may obtain",
		},
		{
			"an issuer with a pattern that does not parse",
			"server:\n  listen_addr: \"0.0.0.0:8080\"\n  tls:\n    listen_addr: \"0.0.0.0:8443\"\n    key_label: \"ca-tls-key-v1\"\n    cert_path: \"tls.pem\"\n",
			"api:\n  issuers:\n    \"urn:a\": {profiles: [tls-client], names: [\"host:*\"]}\n  revokers: [\"urn:a\"]\n",
			"unknown name type",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.server+tc.api+base))
			if err == nil {
				t.Fatal("Load succeeded, want a refusal")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("err = %v, want it to mention %q", err, tc.want)
			}
		})
	}
}
