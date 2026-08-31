// Package config loads the service's configuration file and turns it into
// the runtime objects the rest of the service needs (a *pkcs11.VendorAdapter,
// a resolved session budget). See config.example.yaml for the file format and
// the reasoning behind it — most importantly, that it never holds a PIN
// itself, only the name of the environment variable the PIN is read from
// (CLAUDE.md §3.1, §3.2).
package config

import (
	"fmt"
	"math/big"
	"net/url"
	"os"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/LockedWayi/hsm-pki-platform/internal/ca"
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

// CAConfig configures certificate issuance policy and where the service's
// signing identity lives: the **intermediate's** key pair on the HSM (by
// label) and the ceremony-produced intermediate certificate on disk (by
// path) — see internal/ca.LoadIntermediate for how the two are used
// together.
//
// # What this struct deliberately cannot express
//
// There is no field here naming the root's token, workspace, or key label,
// and adding one would be a defect rather than a feature. The root is
// reachable only from the offline ceremony (internal/ca.RunCeremony,
// cmd/hsm-pki-keytool), so a compromise of this service cannot reach it —
// that is the whole point of the two-tier hierarchy this phase introduced
// (docs/phases/phase-3b-pki-hardening.md, CLAUDE.md §3.6).
//
// RootCertPath and RootCRLPath are not exceptions to that. Both name public
// artifacts the ceremony emitted — a certificate and a CRL, containing no
// key material and conferring no ability to use the root's key. The service
// serves them as static files so that the CDP and AIA URLs baked into the
// intermediate at ceremony time actually resolve; see TestConfig_NoRootKeyReferences,
// which pins the distinction so a future field cannot quietly cross it.
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
	// as a static artifact at the AIA CA-Issuers URL. Public, no key
	// material — see the type's doc comment.
	RootCertPath string `yaml:"root_cert_path"`
	// RootCRLPath is the ceremony-produced root CRL (PEM), served as a
	// static artifact at the intermediate's CRL distribution point. It
	// covers exactly one certificate: the intermediate itself.
	RootCRLPath string `yaml:"root_crl_path"`
	// BaseURL is the externally reachable origin of this service, and the
	// stem of the CRL distribution point and AIA CA-Issuers URL written into
	// every certificate it issues (internal/api.LeafDistributionFor).
	//
	// Required, with no default. There is nothing sensible to default it to:
	// server.listen_addr is what the process binds, which behind a load
	// balancer or an ingress is not what a relying party can resolve, and a
	// wrong guess here is not a startup failure — it is a correctly-signed
	// certificate pointing at a CRL nobody can fetch, discovered by a
	// verifier months later. Getting it wrong is recoverable only by
	// re-issuing every certificate signed since, so the operator states it.
	BaseURL string `yaml:"base_url"`
	// CRLValidityHours is how long a generated CRL is valid for
	// (thisUpdate to nextUpdate). Optional — defaulted by Load when zero.
	CRLValidityHours int `yaml:"crl_validity_hours"`
	// StorePath is the embedded SQLite database holding issued and revoked
	// records and the CRL number counter. Required: losing revocation state
	// on restart is a security regression, so there is no in-memory fallback
	// to default to (internal/store).
	StorePath string `yaml:"store_path"`
	// CRLNumberFloor raises the number a *fresh* store seeds its CRL counter
	// with. Optional, and normally absent.
	//
	// It exists for one recovery case. A rebuilt store seeds its counter
	// from the wall clock, which is above any number the old store issued as
	// long as the clock has not moved backwards. If it has — a restored host
	// with a bad clock, a VM whose time source was wrong — the new sequence
	// could land below numbers verifiers already hold, and RFC 5280 §5.2.3
	// then lets them ignore every CRL this CA issues afterward. Nothing can
	// recover the last number automatically, because the thing that
	// remembered it is what was lost; an operator who does know it sets it
	// here. An existing counter is never affected.
	CRLNumberFloor string `yaml:"crl_number_floor"`
}

// defaultCRLValidityHours is used when ca.crl_validity_hours is left at zero
// in config.yaml.
//
// There is no default subject common name any more: the service no longer
// creates a certificate, so it has no subject to name. The intermediate's
// subject was fixed at ceremony time and is read off the certificate.
const defaultCRLValidityHours = 24

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
	// Present-but-empty is checked, not just present. LookupEnv reports
	// true for PIN="", so a deployment that exports the variable without a
	// value would pass startup validation and then fail at ResolvePIN, at
	// the point of an HSM login — which is both later and further from the
	// cause than it needs to be (CLAUDE.md §3.4). The value is compared
	// against "" and never read into anything that outlives this check.
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
	// Each of these is required rather than defaulted. The service no longer
	// creates a CA when it finds none (see internal/ca.LoadIntermediate), so
	// an unset path is a misconfiguration to report at startup, not a state
	// to repair — and a defaulted path would silently point the service
	// somewhere the operator never chose.
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
		// RFC 5280 §5.2.3 makes the CRL number a non-negative integer, and
		// ca.BuildCRL rejects a non-positive one outright. Catching it here
		// means a typed minus sign fails at startup rather than at the
		// first GET /crl, which is when this field's whole purpose —
		// surviving a rebuilt store — would be needed most.
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
// will end up in demand.
//
// The scheme/host rules are shared with the ceremony's own distribution
// URLs (ca.ValidateDistributionURL) — one rule, one implementation, because
// they are the same rule: a URL that will be embedded in a certificate has
// to be one a relying party can fetch.
//
// The query/fragment rejection is specific to a *base* URL. Path components
// are appended to it, so "https://pki.example.test/?v=1" would compose into
// "https://pki.example.test/?v=1/crl" — a URL that parses, points nowhere,
// and would be discovered only by whoever tried to fetch the CRL.
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
	// time.ParseDuration accepts "-5m" and "0s" happily. A session budget
	// that is zero or negative is not a shorter budget, it is a session
	// that is already over its limit the instant it opens — so it is
	// rejected here rather than handed to the adapter's janitor to
	// interpret (CLAUDE.md §3.4).
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
