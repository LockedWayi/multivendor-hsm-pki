package config

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// withProfiles appends a ca.profiles section to the valid configuration,
// which ends inside the ca block.
func withProfiles(section string) string {
	return validSoftHSM2Config + "  profiles:\n" + section
}

// TestLoad_ProfilesDefaultToTheBuiltins: no section means the four the
// platform ships with, each under the ceiling.
func TestLoad_ProfilesDefaultToTheBuiltins(t *testing.T) {
	t.Setenv("TEST_SOFTHSM2_PIN", "123456")
	cfg, err := Load(writeConfig(t, validSoftHSM2Config))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	names := cfg.CA.ProfileSet.Names()
	if strings.Join(names, ",") != "code-signing,ocsp-responder,tls-client,tls-server" {
		t.Fatalf("ProfileSet.Names() = %v, want the four built-ins", names)
	}
}

// TestLoad_ProfilesSectionReplacesTheBuiltins: a present section is the
// whole set. What it does not name does not exist.
func TestLoad_ProfilesSectionReplacesTheBuiltins(t *testing.T) {
	t.Setenv("TEST_SOFTHSM2_PIN", "123456")
	cfg, err := Load(writeConfig(t, withProfiles(`
    device:
      extended_key_usages: [clientAuth]
      key_usages: [digitalSignature]
      san_types: [uri]
      subject: [CN, OU]
      key_algorithms: [ec-p256]
      validity_hours: 48
`)))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if names := cfg.CA.ProfileSet.Names(); len(names) != 1 || names[0] != "device" {
		t.Fatalf("ProfileSet.Names() = %v, want only the configured profile", names)
	}
	p := cfg.CA.ProfileSet["device"]
	if p.Validity != 48*time.Hour || len(p.SubjectRDNs) != 2 || p.SANRequired {
		t.Fatalf("device = %+v", p)
	}
	if _, err := cfg.CA.ProfileSet.Lookup("tls-client"); err == nil {
		t.Fatal("tls-client still exists after the section replaced the set")
	}
}

// TestLoad_ProfilesRefusals: the closed vocabulary, the ceiling and an
// empty section each fail at load, before a token is touched.
func TestLoad_ProfilesRefusals(t *testing.T) {
	t.Setenv("TEST_SOFTHSM2_PIN", "123456")
	base := `
    p:
      extended_key_usages: [%s]
      key_usages: [%s]
      subject: [CN]
      key_algorithms: [%s]
      validity_hours: %d
`
	cases := []struct {
		name string
		body string
		want string
	}{
		{"unknown extended key usage", withProfiles(sprintf(base, "anyExtendedKeyUsage", "digitalSignature", "ec-p256", 24)), "unknown extended key usage"},
		{"a CA key usage on a leaf", withProfiles(sprintf(base, "clientAuth", "keyCertSign", "ec-p256", 24)), "unknown key usage"},
		{"unknown key algorithm", withProfiles(sprintf(base, "clientAuth", "digitalSignature", "ed25519", 24)), "unknown key algorithm"},
		{"validity above the ceiling", withProfiles(sprintf(base, "clientAuth", "digitalSignature", "ec-p256", 9000)), "exceeds the CA's ceiling"},
		{"zero validity", withProfiles(sprintf(base, "clientAuth", "digitalSignature", "ec-p256", 0)), "validity must be positive"},
		{"an empty section", validSoftHSM2Config + "  profiles: {}\n", "present but empty"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load = %v, want it to say %q", err, tc.want)
			}
		})
	}
}

func sprintf(format string, args ...any) string {
	return fmt.Sprintf(format, args...)
}

// withOCSP appends a ca.ocsp block to the valid configuration.
func withOCSP(keyLabel string) string {
	return validSoftHSM2Config + "  ocsp:\n    key_label: \"" + keyLabel + "\"\n"
}

// TestLoad_OCSP: the block is optional; when present the key is its own,
// and the profile the responder is issued under must exist.
func TestLoad_OCSP(t *testing.T) {
	t.Setenv("TEST_SOFTHSM2_PIN", "123456")
	cfg, err := Load(writeConfig(t, validSoftHSM2Config))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.CA.OCSP != nil {
		t.Fatalf("OCSP = %+v, want nil when absent", cfg.CA.OCSP)
	}
	cfg, err = Load(writeConfig(t, withOCSP("ocsp-signing-key-v1")))
	if err != nil {
		t.Fatalf("Load with ocsp: %v", err)
	}
	if cfg.CA.OCSP == nil || cfg.CA.OCSP.KeyLabel != "ocsp-signing-key-v1" {
		t.Fatalf("OCSP = %+v", cfg.CA.OCSP)
	}
	for _, tc := range []struct{ name, body, want string }{
		{"empty label", withOCSP(""), "ca.ocsp.key_label is empty"},
		{"the intermediate's label", withOCSP("ca-intermediate-key-v1"), "is the intermediate's key label"},
		{"no ocsp-responder profile", withProfiles(`
    tls-client:
      extended_key_usages: [clientAuth]
      key_usages: [digitalSignature]
      subject: [CN]
      key_algorithms: [ec-p256]
      validity_hours: 24
`) + "  ocsp:\n    key_label: \"ocsp-signing-key-v1\"\n", "does not define \"ocsp-responder\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(writeConfig(t, tc.body))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Load = %v, want it to say %q", err, tc.want)
			}
		})
	}
}
