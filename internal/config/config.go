// Package config loads the service's configuration file and builds the
// runtime objects the service needs. The file never holds a PIN, only the
// name of the environment variable the PIN is read from.
package config

import (
	"fmt"
	"math/big"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/entitlement"
	pkcs11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/profile"
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
	API    APIConfig    `yaml:"api"`
}

// ServerConfig configures the listeners. ListenAddr serves the public
// surface over plain HTTP: the CRLs, the certificates and the probes,
// which a relying party fetches with no credential. TLS, when present,
// adds the authenticated listener that carries the write endpoints.
// Without it the service issues and revokes nothing: there is no plain
// HTTP path to a write endpoint.
type ServerConfig struct {
	ListenAddr string     `yaml:"listen_addr"`
	TLS        *TLSConfig `yaml:"tls"`
}

// TLSConfig configures the authenticated listener. The service's TLS key
// lives on the token this service authenticates, beside the
// intermediate, under its own label. The certificate is a leaf this CA
// issued over that key. Clients are verified against the ceremony root
// named by ca.root_cert_path; there is no separate client CA, because
// the clients are certificates this CA issued.
type TLSConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	// KeyLabel is the CKA_LABEL of the TLS key pair. Never the
	// intermediate's label: Load refuses that.
	KeyLabel string `yaml:"key_label"`
	// CertPath is the TLS certificate, PEM, one certificate.
	CertPath string `yaml:"cert_path"`
}

// APIConfig names the clients that may write, by an identity off their
// certificate: a URI SAN as written, or the subject common name. Both
// lists are required when server.tls is configured, and refused when it
// is not, because without the authenticated listener nobody can reach
// the endpoints they authorise.
type APIConfig struct {
	// Issuers may POST /certificates, each for the profiles and the name
	// patterns its entry grants. An identity absent here issues nothing;
	// an entry granting nothing is refused at load. Written as a map
	// from identity to {profiles, names}; the earlier list form fails to
	// parse, which is the intended way for a stale configuration to
	// announce itself.
	Issuers map[string]entitlement.Spec `yaml:"issuers"`
	// Entitlements is derived from Issuers by Load.
	Entitlements entitlement.Map `yaml:"-"`
	// Revokers may POST /certificates/{serial}/revoke. Not defaulted from
	// Issuers: who may withdraw a certificate is a separate decision, and
	// during an incident it is the one that matters.
	Revokers []string `yaml:"revokers"`
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
	CurveName string `yaml:"curve"`
	// CertTTLHours is the ceiling: no profile may grant a longer validity.
	// Since profiles exist it no longer sets any certificate's lifetime
	// itself; the profile does. Startup refuses a profile above it, and
	// Issue checks again at the point of use.
	CertTTLHours int `yaml:"cert_ttl_hours"`
	// Profiles replaces the built-in set (profile.Builtin) when present.
	// Absent means the built-ins; present and empty is refused. A request
	// names one of these, and one it does not name is refused: there is
	// no default profile.
	Profiles map[string]profile.Spec `yaml:"profiles"`
	// ProfileSet is derived from Profiles by Load.
	ProfileSet profile.Set `yaml:"-"`
	// OCSP configures the delegated responder. Absent means none: no
	// route, no OCSP pointer in issued certificates.
	OCSP *OCSPConfig `yaml:"ocsp"`
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

// OCSPConfig configures the delegated OCSP responder. The responder key
// lives on the token this service authenticates, beside the intermediate,
// under its own versioned label, provisioned by hsm-pki-keytool
// provision-ocsp-key. Its certificate is issued by the service itself on
// the internal path under the ocsp-responder profile and renewed
// automatically; nothing here names a certificate file.
type OCSPConfig struct {
	// KeyLabel is the CKA_LABEL of the responder key pair. Never the
	// intermediate's label, and never the TLS key's: Load refuses both.
	KeyLabel string `yaml:"key_label"`
	// Subject is the responder certificate's common name. Defaulted from
	// the intermediate's when empty.
	Subject string `yaml:"subject"`
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
	profiles, err := loadProfiles(c.CA.Profiles, time.Duration(c.CA.CertTTLHours)*time.Hour)
	if err != nil {
		return nil, err
	}
	c.CA.ProfileSet = profiles
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
	if err := c.validateAuthenticatedSurface(); err != nil {
		return nil, err
	}
	if err := c.validateOCSP(); err != nil {
		return nil, err
	}

	return &c, nil
}

// validateOCSP checks the responder block. The responder key signs
// status responses and nothing else, so it is neither the intermediate's
// key nor the TLS key, and the profile it is issued under must exist.
func (c *Config) validateOCSP() error {
	o := c.CA.OCSP
	if o == nil {
		return nil
	}
	if o.KeyLabel == "" {
		return fmt.Errorf("config: ca.ocsp.key_label is empty")
	}
	if o.KeyLabel == c.CA.IntermediateKeyLabel {
		return fmt.Errorf("config: ca.ocsp.key_label %q is the intermediate's key label; the responder needs its own key, because a compromised responder key must be able to lie about status and nothing else", o.KeyLabel)
	}
	if c.Server.TLS != nil && o.KeyLabel == c.Server.TLS.KeyLabel {
		return fmt.Errorf("config: ca.ocsp.key_label %q is the TLS key's label; one key, one purpose", o.KeyLabel)
	}
	if _, err := c.CA.ProfileSet.Lookup(profile.InternalOnlyProfile); err != nil {
		return fmt.Errorf("config: ca.ocsp is set but ca.profiles does not define %q, which the responder's certificate is issued under", profile.InternalOnlyProfile)
	}
	return nil
}

// loadProfiles compiles ca.profiles, or takes the built-ins when the
// section is absent, and validates the result against the ceiling. An
// unknown name in any list is refused here, so a typo cannot become a
// certificate that asserts less, or more, than the operator meant.
func loadProfiles(specs map[string]profile.Spec, ceiling time.Duration) (profile.Set, error) {
	var set profile.Set
	if specs == nil {
		set = profile.Builtin()
	} else {
		parsed, err := profile.Parse(specs)
		if err != nil {
			return nil, fmt.Errorf("config: ca.profiles: %w", err)
		}
		set = parsed
	}
	if err := set.Validate(ceiling); err != nil {
		return nil, fmt.Errorf("config: ca.profiles: %w", err)
	}
	return set, nil
}

// validateAuthenticatedSurface checks server.tls and api together. Either
// both are configured or neither is: a TLS listener with nobody
// authorised serves write endpoints that refuse everyone, and an
// authorisation list with no TLS listener names clients who cannot
// connect. Both read as configured and do nothing.
func (c *Config) validateAuthenticatedSurface() error {
	tlsCfg := c.Server.TLS
	if tlsCfg == nil {
		if len(c.API.Issuers) > 0 || len(c.API.Revokers) > 0 {
			return fmt.Errorf("config: api.issuers or api.revokers is set but server.tls is not; the write endpoints are served over mutual TLS only, so nobody named there could reach them")
		}
		return nil
	}
	for field, v := range map[string]string{
		"server.tls.listen_addr": tlsCfg.ListenAddr,
		"server.tls.key_label":   tlsCfg.KeyLabel,
		"server.tls.cert_path":   tlsCfg.CertPath,
	} {
		if v == "" {
			return fmt.Errorf("config: %s is empty", field)
		}
	}
	if tlsCfg.ListenAddr == c.Server.ListenAddr {
		return fmt.Errorf("config: server.tls.listen_addr %q is the same as server.listen_addr; the public and the authenticated surfaces need their own listeners", tlsCfg.ListenAddr)
	}
	// The TLS key signs whatever bytes a connecting client makes the
	// handshake sign. That must never be the key that signs certificates.
	if tlsCfg.KeyLabel == c.CA.IntermediateKeyLabel {
		return fmt.Errorf("config: server.tls.key_label %q is the intermediate's key label; the TLS identity needs its own key pair, because a handshake signs bytes the peer chooses", tlsCfg.KeyLabel)
	}
	if len(c.API.Issuers) == 0 {
		return fmt.Errorf("config: api.issuers is empty; server.tls is configured, so name at least one client identity, or nobody can use that endpoint")
	}
	ents, err := entitlement.Parse(c.API.Issuers)
	if err != nil {
		return fmt.Errorf("config: api.issuers: %w", err)
	}
	// Every profile an entitlement grants must exist, or the grant is a
	// typo that reads as a permission until somebody tries to use it.
	for _, identity := range ents.Identities() {
		for _, name := range ents[identity].Profiles() {
			if _, err := c.CA.ProfileSet.Lookup(name); err != nil {
				return fmt.Errorf("config: api.issuers: %q is granted profile %q, which ca.profiles does not define (available: %s)", identity, name, strings.Join(c.CA.ProfileSet.Names(), ", "))
			}
		}
	}
	c.API.Entitlements = ents

	if len(c.API.Revokers) == 0 {
		return fmt.Errorf("config: api.revokers is empty; server.tls is configured, so name at least one client identity, or nobody can use that endpoint")
	}
	seen := make(map[string]bool, len(c.API.Revokers))
	for _, id := range c.API.Revokers {
		if id == "" {
			return fmt.Errorf("config: api.revokers contains an empty identity")
		}
		if seen[id] {
			return fmt.Errorf("config: api.revokers lists %q twice", id)
		}
		seen[id] = true
	}
	return nil
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
