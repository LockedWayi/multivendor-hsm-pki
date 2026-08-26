// Package config loads the service's configuration file and turns it into
// the runtime objects the rest of the service needs (a *pkcs11.VendorAdapter,
// a resolved session budget). See config.example.yaml for the file format and
// the reasoning behind it — most importantly, that it never holds a PIN
// itself, only the name of the environment variable the PIN is read from
// (CLAUDE.md §3.1, §3.2).
package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	pkcs11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

// Adapter names accepted by pkcs11.adapter in the config file.
const (
	AdapterSoftHSM2      = "softhsm2"
	AdapterProtectServer = "protectserver"
)

// Config is the parsed form of config.yaml.
type Config struct {
	Server ServerConfig `yaml:"server"`
	PKCS11 PKCS11Config `yaml:"pkcs11"`
	CA     CAConfig     `yaml:"ca"`
}

// ServerConfig configures the HTTP listener.
type ServerConfig struct {
	ListenAddr string `yaml:"listen_addr"`
}

// PKCS11Config selects and configures the vendor adapter.
type PKCS11Config struct {
	Adapter       string        `yaml:"adapter"`
	Session       SessionConfig `yaml:"session"`
	SoftHSM2      *VendorConfig `yaml:"softhsm2"`
	ProtectServer *VendorConfig `yaml:"protectserver"`

	// SessionOptions is derived from Session by Load. Use this field, not
	// Session, once a Config has come back from Load — Session only holds
	// the raw, not-yet-parsed YAML strings.
	SessionOptions pkcs11.SessionOptions `yaml:"-"`
}

// SessionConfig carries the session budget as the raw strings from YAML
// (e.g. "15m", "8h"); Load parses these into a pkcs11.SessionOptions.
type SessionConfig struct {
	IdleTimeout string `yaml:"idle_timeout"`
	MaxTTL      string `yaml:"max_ttl"`
}

// VendorConfig configures one PKCS#11 backend. PINEnv names the environment
// variable the login PIN is read from — never a literal PIN value.
type VendorConfig struct {
	ModulePath     string `yaml:"module_path"`
	WorkspaceLabel string `yaml:"workspace_label"`
	PINEnv         string `yaml:"pin_env"`
}

// CAConfig configures certificate issuance policy and where the CA's own
// identity lives: its key pair on the HSM (by label) and its self-signed
// certificate on disk (by path) — see internal/ca.Bootstrap for how the two
// are used together.
type CAConfig struct {
	CurveName    string `yaml:"curve"`
	CertTTLHours int    `yaml:"cert_ttl_hours"`
	KeyLabel     string `yaml:"key_label"`
	CertPath     string `yaml:"cert_path"`
	// SubjectCommonName names the CA's own certificate subject. Optional —
	// defaulted by Load when empty, since it is not security-relevant the
	// way the PIN/module/label fields are.
	SubjectCommonName string `yaml:"subject_common_name"`
	// CRLValidityHours is how long a generated CRL is valid for
	// (thisUpdate to nextUpdate). Optional — defaulted by Load when zero.
	CRLValidityHours int `yaml:"crl_validity_hours"`
}

const (
	// defaultSubjectCommonName is used when ca.subject_common_name is left
	// empty in config.yaml.
	defaultSubjectCommonName = "hsm-pki-platform CA"
	// defaultCRLValidityHours is used when ca.crl_validity_hours is left
	// at zero in config.yaml.
	defaultCRLValidityHours = 24
)

// Load reads and validates the config file at path. Validation is
// deliberately strict and fails fast: an unknown adapter name or a missing
// PIN environment variable is rejected here, before anything tries to open
// an HSM session (CLAUDE.md §3.4, fail closed).
//
// Load never reads the PIN's value — only confirms the environment variable
// named by pin_env is set. The value itself is read once, at the point of
// use, by ResolvePIN.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: reading %s: %w", path, err)
	}
	var c Config
	if err := yaml.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("config: parsing %s: %w", path, err)
	}

	vendor, err := c.PKCS11.selectedVendor()
	if err != nil {
		return nil, err
	}
	if vendor.ModulePath == "" {
		return nil, fmt.Errorf("config: pkcs11.%s.module_path is empty", c.PKCS11.Adapter)
	}
	if vendor.WorkspaceLabel == "" {
		return nil, fmt.Errorf("config: pkcs11.%s.workspace_label is empty", c.PKCS11.Adapter)
	}
	if vendor.PINEnv == "" {
		return nil, fmt.Errorf("config: pkcs11.%s.pin_env is empty", c.PKCS11.Adapter)
	}
	if _, ok := os.LookupEnv(vendor.PINEnv); !ok {
		return nil, fmt.Errorf("config: environment variable %s (pkcs11.%s.pin_env) is not set",
			vendor.PINEnv, c.PKCS11.Adapter)
	}

	opts, err := c.PKCS11.Session.parse()
	if err != nil {
		return nil, err
	}
	c.PKCS11.SessionOptions = opts

	if _, err := ParseCurve(c.CA.CurveName); err != nil {
		return nil, err
	}
	if c.CA.CertTTLHours <= 0 {
		return nil, fmt.Errorf("config: ca.cert_ttl_hours must be positive, got %d", c.CA.CertTTLHours)
	}
	if c.CA.KeyLabel == "" {
		return nil, fmt.Errorf("config: ca.key_label is empty")
	}
	if c.CA.CertPath == "" {
		return nil, fmt.Errorf("config: ca.cert_path is empty")
	}
	if c.CA.SubjectCommonName == "" {
		c.CA.SubjectCommonName = defaultSubjectCommonName
	}
	if c.CA.CRLValidityHours == 0 {
		c.CA.CRLValidityHours = defaultCRLValidityHours
	}

	return &c, nil
}

// ParseCurve maps a config ca.curve string to a pkcs11.ECCurve.
func ParseCurve(s string) (pkcs11.ECCurve, error) {
	switch s {
	case "P-256":
		return pkcs11.P256, nil
	case "P-384":
		return pkcs11.P384, nil
	case "P-521":
		return pkcs11.P521, nil
	default:
		return 0, fmt.Errorf("config: unknown ca.curve %q (want \"P-256\", \"P-384\", or \"P-521\")", s)
	}
}

// Curve returns the parsed pkcs11.ECCurve for ca.curve. Load already
// validated it, so this is safe to call unchecked afterward.
func (c *CAConfig) Curve() pkcs11.ECCurve {
	curve, _ := ParseCurve(c.CurveName)
	return curve
}

// selectedVendor returns the VendorConfig for whichever adapter
// pkcs11.adapter names, or an error if that name is unknown or its block is
// missing from the config file.
func (p *PKCS11Config) selectedVendor() (*VendorConfig, error) {
	switch p.Adapter {
	case AdapterSoftHSM2:
		if p.SoftHSM2 == nil {
			return nil, fmt.Errorf("config: pkcs11.adapter is %q but pkcs11.softhsm2 is not configured", p.Adapter)
		}
		return p.SoftHSM2, nil
	case AdapterProtectServer:
		if p.ProtectServer == nil {
			return nil, fmt.Errorf("config: pkcs11.adapter is %q but pkcs11.protectserver is not configured", p.Adapter)
		}
		return p.ProtectServer, nil
	default:
		return nil, fmt.Errorf("config: unknown pkcs11.adapter %q (want %q or %q)",
			p.Adapter, AdapterSoftHSM2, AdapterProtectServer)
	}
}

// parse turns the raw idle_timeout/max_ttl strings into a
// pkcs11.SessionOptions, defaulting either one that was left empty.
func (s SessionConfig) parse() (pkcs11.SessionOptions, error) {
	d := pkcs11.DefaultSessionOptions()
	if s.IdleTimeout != "" {
		v, err := time.ParseDuration(s.IdleTimeout)
		if err != nil {
			return pkcs11.SessionOptions{}, fmt.Errorf("config: pkcs11.session.idle_timeout: %w", err)
		}
		d.IdleTimeout = v
	}
	if s.MaxTTL != "" {
		v, err := time.ParseDuration(s.MaxTTL)
		if err != nil {
			return pkcs11.SessionOptions{}, fmt.Errorf("config: pkcs11.session.max_ttl: %w", err)
		}
		d.MaxTTL = v
	}
	return d, nil
}

// Vendor returns the VendorConfig for the configured adapter. Load already
// validated it exists; this is for callers that only have a *Config.
func (c *Config) Vendor() (*VendorConfig, error) {
	return c.PKCS11.selectedVendor()
}

// NewVendorAdapter constructs the pkcs11.VendorAdapter named by
// pkcs11.adapter. It only loads and initializes the PKCS#11 module — it does
// not open a session or log in; callers do that afterward (see
// cmd/hsm-pki-server for the startup sequence that proves the connection
// actually works before serving traffic).
func (c *Config) NewVendorAdapter() (pkcs11.VendorAdapter, error) {
	vendor, err := c.PKCS11.selectedVendor()
	if err != nil {
		return nil, err
	}
	switch c.PKCS11.Adapter {
	case AdapterSoftHSM2:
		return pkcs11.NewSoftHSM2Adapter(vendor.ModulePath)
	case AdapterProtectServer:
		return pkcs11.NewProtectServerAdapter(vendor.ModulePath)
	default:
		// Unreachable: selectedVendor already rejected any other value.
		return nil, fmt.Errorf("config: unknown pkcs11.adapter %q", c.PKCS11.Adapter)
	}
}

// ResolvePIN reads the login PIN from the environment variable named by the
// configured adapter's pin_env, at the point of use — it is never cached on
// Config, so its lifetime as a value this package is responsible for is as
// short as the call chain from here to pkcs11.SecurePIN's construction.
func (c *Config) ResolvePIN() ([]byte, error) {
	vendor, err := c.PKCS11.selectedVendor()
	if err != nil {
		return nil, err
	}
	pin := os.Getenv(vendor.PINEnv)
	if pin == "" {
		return nil, fmt.Errorf("config: environment variable %s is not set", vendor.PINEnv)
	}
	return []byte(pin), nil
}
