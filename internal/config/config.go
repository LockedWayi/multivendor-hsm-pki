// Package config loads the service's configuration file and builds the
// runtime objects the service needs. The file never holds a PIN, only the
// name of the environment variable the PIN is read from.
package config

import (
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	pkcs11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
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

	// SessionOptions is derived from Session by Load. Session holds the raw
	// YAML strings.
	SessionOptions pkcs11.SessionOptions `yaml:"-"`
}

// SessionConfig carries the session budget as the raw strings from YAML
// (e.g. "15m", "8h"); Load parses these into a pkcs11.SessionOptions.
type SessionConfig struct {
	IdleTimeout string `yaml:"idle_timeout"`
	MaxTTL      string `yaml:"max_ttl"`
}

// VendorConfig configures one PKCS#11 backend. PINEnv names the environment
// variable the login PIN is read from, never a literal PIN value.
type VendorConfig struct {
	ModulePath     string `yaml:"module_path"`
	WorkspaceLabel string `yaml:"workspace_label"`
	PINEnv         string `yaml:"pin_env"`
}

// CAConfig configures issuance and where the service's signing identity
// lives: the intermediate's key pair on the token, by label, and the
// ceremony-produced intermediate certificate on disk, by path.
//
// There is no field naming the root's token, workspace or key label, and
// adding one is a defect. The root is reachable only from the offline
// ceremony. RootCertPath and RootCRLPath name public artifacts with no key
// material. TestConfig_NoRootKeyReferences pins the distinction.
type CAConfig struct {
	CurveName    string `yaml:"curve"`
	CertTTLHours int    `yaml:"cert_ttl_hours"`
	// IntermediateKeyLabel is the CKA_LABEL of the intermediate key pair the
	// ceremony created, on the token this service authenticates.
	IntermediateKeyLabel string `yaml:"intermediate_key_label"`
	// IntermediateCertPath is the ceremony-produced intermediate certificate
	// (PEM). The service refuses to start if it is self-signed.
	IntermediateCertPath string `yaml:"intermediate_cert_path"`
	// RootCertPath is the ceremony-produced root certificate (PEM), served
	// at the AIA CA-Issuers URL. Public.
	RootCertPath string `yaml:"root_cert_path"`
	// RootCRLPath is the ceremony-produced root CRL (PEM), served as a
	// static artifact at the intermediate's CRL distribution point. It
	// covers exactly one certificate: the intermediate itself.
	RootCRLPath string `yaml:"root_crl_path"`
	// BaseURL is the origin a relying party can resolve, and the stem of
	// the CRL distribution point and AIA URL in every issued certificate.
	// Required, with no default. server.listen_addr is what the process
	// binds, which behind a load balancer is not resolvable. A wrong value
	// is a correctly signed certificate pointing at a CRL nobody can fetch,
	// and every certificate signed since has to be re-issued.
	BaseURL string `yaml:"base_url"`
	// CRLValidityHours is how long a generated CRL is valid for
	// (thisUpdate to nextUpdate). Optional, defaulted by Load when zero.
	CRLValidityHours int `yaml:"crl_validity_hours"`
	// StorePath is the embedded SQLite database. Required: losing
	// revocation state on restart is a security regression, so there is no
	// in-memory fallback.
	StorePath string `yaml:"store_path"`
	// CRLNumberFloor raises the number a fresh store seeds its CRL counter
	// with. Normally absent. A rebuilt store seeds from the wall clock;
	// when the clock has moved backwards, the sequence could land below
	// numbers verifiers hold, and RFC 5280 §5.2.3 lets them ignore every
	// later CRL. An operator who knows the last number sets it here. An
	// existing counter is never affected.
	CRLNumberFloor string `yaml:"crl_number_floor"`
}

// defaultCRLValidityHours applies when ca.crl_validity_hours is zero.
const defaultCRLValidityHours = 24

// Load reads and validates the config file at path. An unknown adapter
// name or a missing PIN environment variable is rejected here, before any
// token is opened. Load never reads the PIN's value; it only confirms the
// variable is set and not empty. ResolvePIN reads the value at the point
// of use.
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
	// Present but empty is checked too. LookupEnv reports true for PIN="",
	// and the failure would otherwise surface at the token login.
	if pin, ok := os.LookupEnv(vendor.PINEnv); !ok {
		return nil, fmt.Errorf("config: environment variable %s (pkcs11.%s.pin_env) is not set",
			vendor.PINEnv, c.PKCS11.Adapter)
	} else if pin == "" {
		return nil, fmt.Errorf("config: environment variable %s (pkcs11.%s.pin_env) is set but empty",
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
	// Required, not defaulted. The service never creates a CA when it finds
	// none, and a defaulted path would point somewhere the operator did not
	// choose.
	for field, v := range map[string]string{
		"ca.intermediate_key_label": c.CA.IntermediateKeyLabel,
		"ca.intermediate_cert_path": c.CA.IntermediateCertPath,
		"ca.root_cert_path":         c.CA.RootCertPath,
		"ca.root_crl_path":          c.CA.RootCRLPath,
		"ca.store_path":             c.CA.StorePath,
		"ca.base_url":               c.CA.BaseURL,
	} {
		if v == "" {
			return nil, fmt.Errorf("config: %s is empty", field)
		}
	}
	if err := validateBaseURL(c.CA.BaseURL); err != nil {
		return nil, err
	}
	if c.CA.CRLNumberFloor != "" {
		floor, ok := new(big.Int).SetString(c.CA.CRLNumberFloor, 10)
		if !ok {
			return nil, fmt.Errorf("config: ca.crl_number_floor %q is not a decimal integer", c.CA.CRLNumberFloor)
		}
		// A negative number fails here rather than at the first GET /crl.
		if floor.Sign() < 0 {
			return nil, fmt.Errorf("config: ca.crl_number_floor %q is negative; RFC 5280 §5.2.3 CRL numbers are non-negative", c.CA.CRLNumberFloor)
		}
	}
	if c.CA.CRLValidityHours == 0 {
		c.CA.CRLValidityHours = defaultCRLValidityHours
	}

	return &c, nil
}

// validateBaseURL checks ca.base_url the way the certificate extensions it
// ends up in demand. The scheme and host rules are ca.ValidateDistributionURL's.
// A query or fragment is refused because paths are appended to the base:
// "https://pki.example.test/?v=1" would compose into a URL that parses and
// points nowhere.
func validateBaseURL(raw string) error {
	if err := ca.ValidateDistributionURL("ca.base_url", raw); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("config: ca.base_url is not a valid URL: %w", err)
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return fmt.Errorf("config: ca.base_url %q must not carry a query string or fragment: certificate paths are appended to it", raw)
	}
	return nil
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

// CRLFloor returns the parsed ca.crl_number_floor, or nil when unset. Load
// already validated it, so this is safe to call unchecked afterward.
func (c *CAConfig) CRLFloor() *big.Int {
	if c.CRLNumberFloor == "" {
		return nil
	}
	n, _ := new(big.Int).SetString(c.CRLNumberFloor, 10)
	return n
}

// Curve returns the parsed pkcs11.ECCurve for ca.curve. Load already
// validated it, so this is safe to call unchecked afterward.
func (c *CAConfig) Curve() pkcs11.ECCurve {
	curve, _ := ParseCurve(c.CurveName)
	return curve
}

// selectedVendor returns the VendorConfig for the adapter pkcs11.adapter
// names.
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
	// A zero or negative budget is a session that is over its limit the
	// instant it opens. Rejected here.
	if s.IdleTimeout != "" {
		v, err := time.ParseDuration(s.IdleTimeout)
		if err != nil {
			return pkcs11.SessionOptions{}, fmt.Errorf("config: pkcs11.session.idle_timeout: %w", err)
		}
		if v <= 0 {
			return pkcs11.SessionOptions{}, fmt.Errorf("config: pkcs11.session.idle_timeout must be positive, got %s", v)
		}
		d.IdleTimeout = v
	}
	if s.MaxTTL != "" {
		v, err := time.ParseDuration(s.MaxTTL)
		if err != nil {
			return pkcs11.SessionOptions{}, fmt.Errorf("config: pkcs11.session.max_ttl: %w", err)
		}
		if v <= 0 {
			return pkcs11.SessionOptions{}, fmt.Errorf("config: pkcs11.session.max_ttl must be positive, got %s", v)
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

// NewVendorAdapter loads and initializes the PKCS#11 module named by
// pkcs11.adapter. It opens no session and does not log in.
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

// ResolvePIN reads the PIN from the configured environment variable at the
// point of use. It is never cached on Config.
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
