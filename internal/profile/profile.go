// Package profile defines what a certificate this CA issues may contain.
//
// A profile is the whole of the issuance policy for one kind of
// certificate: which extended key usages and key usages it asserts, which
// subject alternative name types it may carry and whether it must carry
// one, which subject attributes are copied from the request, which key
// algorithms are accepted, how long it is valid for. The CA fills a
// certificate template from a profile and from nothing else, so a field
// no profile names cannot be requested.
//
// There is no default profile. A request that names none, or one the
// service does not know, is refused: defaulting to tls-server would
// re-create the pre-profile behaviour behind a policy-shaped facade.
//
// Builtin returns the four profiles the platform ships with. A
// deployment may replace them in its configuration; the vocabulary each
// field accepts is fixed here, so a profile cannot express something the
// CA does not know how to enforce.
package profile

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ErrUnknownProfile reports a name no profile in the set carries.
var ErrUnknownProfile = errors.New("profile: unknown profile")

// InternalOnlyProfile is the one profile no client identity may be
// granted: the delegated OCSP responder's certificate is issued on the
// internal path, never over the API. Whatever the configuration says, an
// entitlement naming it is refused at load and again at the point of use.
const InternalOnlyProfile = "ocsp-responder"

// InternalOnly reports whether name is a profile no client may obtain.
func InternalOnly(name string) bool { return name == InternalOnlyProfile }

// SANType is one subject-alternative-name type a profile may allow.
type SANType string

// The four SAN types this CA copies from a request. Others in a request
// are refused.
const (
	SANDNS   SANType = "dns"
	SANIP    SANType = "ip"
	SANURI   SANType = "uri"
	SANEmail SANType = "email"
)

// KeyAlgorithm is one public-key algorithm a profile may accept.
type KeyAlgorithm string

// The key algorithms this CA signs for. RSA means 2048 bits or more, the
// floor NIST and the CA/Browser Forum accept; shorter is refused by the
// CA before any profile is consulted.
const (
	KeyECP256 KeyAlgorithm = "ec-p256"
	KeyECP384 KeyAlgorithm = "ec-p384"
	KeyECP521 KeyAlgorithm = "ec-p521"
	KeyRSA    KeyAlgorithm = "rsa"
)

// MinRSAKeyBits is the smallest RSA modulus KeyRSA accepts.
const MinRSAKeyBits = 2048

// OIDOCSPNoCheck is id-pkix-ocsp-nocheck (RFC 6960 §4.2.2.2.1). A
// responder certificate carrying it tells relying parties not to check
// its revocation status, which is why such a certificate must be
// short-lived.
var OIDOCSPNoCheck = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 48, 1, 5}

// Profile is one issuance policy. Every field is what the certificate
// will carry, not a hint: the CA copies from the request only what the
// profile allows and refuses the rest.
type Profile struct {
	Name string

	// ExtKeyUsages are asserted exactly, none added.
	ExtKeyUsages []x509.ExtKeyUsage
	// KeyUsage is the most the certificate asserts. keyEncipherment is
	// an RSA operation (RFC 5480 §3), so a certificate over an EC key
	// does not carry it even when the profile lists it.
	KeyUsage x509.KeyUsage

	// SANTypes are the subject-alternative-name types copied from the
	// request. A request carrying any other type is refused, not
	// trimmed: a caller who asked for a name they will not get should
	// hear so.
	SANTypes []SANType
	// SANRequired refuses a request with no name of an allowed type. A
	// server certificate identified only by its subject is one no modern
	// client accepts; a client certificate identified by its subject is
	// ordinary.
	SANRequired bool

	// SubjectRDNs are the attribute types copied from the request's
	// subject, by short name (CN, O, OU, C, ST, L). Any other attribute
	// in the request is refused. Without this an issuer chooses its own
	// organisation and country.
	SubjectRDNs []string

	// KeyAlgorithms the request's public key must be one of.
	KeyAlgorithms []KeyAlgorithm

	// Validity is the certificate's lifetime from issuance.
	Validity time.Duration

	// OCSPNoCheck adds id-pkix-ocsp-nocheck. Only a delegated OCSP
	// responder certificate wants it.
	OCSPNoCheck bool
}

// Set is the profiles a service issues under, by name.
type Set map[string]*Profile

// Lookup returns the profile called name, or ErrUnknownProfile. An empty
// name is unknown too; there is no default.
func (s Set) Lookup(name string) (*Profile, error) {
	if name == "" {
		return nil, fmt.Errorf("%w: no profile named in the request", ErrUnknownProfile)
	}
	p, ok := s[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProfile, name)
	}
	return p, nil
}

// Names lists the set's profile names, sorted, for messages and logs.
func (s Set) Names() []string {
	names := make([]string, 0, len(s))
	for n := range s {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// Validate checks every profile in the set and that none outlives
// maxValidity, the ceiling the CA's configuration sets.
func (s Set) Validate(maxValidity time.Duration) error {
	if len(s) == 0 {
		return errors.New("profile: no profiles defined; a CA with no profile issues nothing")
	}
	for name, p := range s {
		if p == nil {
			return fmt.Errorf("profile %q: nil", name)
		}
		if p.Name != name {
			return fmt.Errorf("profile %q: carries the name %q", name, p.Name)
		}
		if err := p.Validate(); err != nil {
			return err
		}
		if maxValidity > 0 && p.Validity > maxValidity {
			return fmt.Errorf("profile %q: validity %s exceeds the CA's ceiling of %s (ca.cert_ttl_hours)", name, p.Validity, maxValidity)
		}
	}
	return nil
}

// Validate checks one profile for internal consistency: something to
// assert, a lifetime, at least one key algorithm, no CA key usages, and
// a SAN requirement that names a type it could be met with.
func (p *Profile) Validate() error {
	if p.Name == "" {
		return errors.New("profile: name is empty")
	}
	if len(p.ExtKeyUsages) == 0 {
		return fmt.Errorf("profile %q: no extended key usage; a certificate good for nothing in particular is good for anything", p.Name)
	}
	if p.KeyUsage == 0 {
		return fmt.Errorf("profile %q: no key usage", p.Name)
	}
	if p.KeyUsage&(x509.KeyUsageCertSign|x509.KeyUsageCRLSign) != 0 {
		return fmt.Errorf("profile %q: keyCertSign or cRLSign on a leaf profile; only the ceremony issues CA certificates", p.Name)
	}
	if p.Validity <= 0 {
		return fmt.Errorf("profile %q: validity must be positive", p.Name)
	}
	if len(p.KeyAlgorithms) == 0 {
		return fmt.Errorf("profile %q: no key algorithm accepted", p.Name)
	}
	if p.SANRequired && len(p.SANTypes) == 0 {
		return fmt.Errorf("profile %q: requires a subject alternative name but allows no type", p.Name)
	}
	if len(p.SubjectRDNs) == 0 && !p.SANRequired {
		return fmt.Errorf("profile %q: copies no subject attribute and requires no SAN, so it could issue a certificate that names nothing", p.Name)
	}
	for _, rdn := range p.SubjectRDNs {
		if _, ok := rdnOIDs[rdn]; !ok {
			return fmt.Errorf("profile %q: subject attribute %q is not one of %s", p.Name, rdn, rdnNames())
		}
	}
	return nil
}

// AllowsKey reports whether pub is an algorithm the profile accepts.
func (p *Profile) AllowsKey(pub any) error {
	var have KeyAlgorithm
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			have = KeyECP256
		case elliptic.P384():
			have = KeyECP384
		case elliptic.P521():
			have = KeyECP521
		default:
			return fmt.Errorf("profile %q: EC curve %s is not accepted", p.Name, k.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		if k.N.BitLen() < MinRSAKeyBits {
			return fmt.Errorf("profile %q: RSA key is %d bits, want at least %d", p.Name, k.N.BitLen(), MinRSAKeyBits)
		}
		have = KeyRSA
	default:
		return fmt.Errorf("profile %q: key type %T is not accepted", p.Name, pub)
	}
	for _, a := range p.KeyAlgorithms {
		if a == have {
			return nil
		}
	}
	return fmt.Errorf("profile %q: key algorithm %s is not accepted (want one of %v)", p.Name, have, p.KeyAlgorithms)
}

// CheckSANs refuses a request carrying a name type the profile does not
// copy, and, when the profile requires a name, a request with none.
func (p *Profile) CheckSANs(csr *x509.CertificateRequest) error {
	allowed := func(t SANType) bool {
		for _, a := range p.SANTypes {
			if a == t {
				return true
			}
		}
		return false
	}
	present := 0
	for t, n := range map[SANType]int{
		SANDNS:   len(csr.DNSNames),
		SANIP:    len(csr.IPAddresses),
		SANURI:   len(csr.URIs),
		SANEmail: len(csr.EmailAddresses),
	} {
		if n == 0 {
			continue
		}
		if !allowed(t) {
			return fmt.Errorf("profile %q: a %s subject alternative name is not allowed", p.Name, t)
		}
		present += n
	}
	if p.SANRequired && present == 0 {
		return fmt.Errorf("profile %q: at least one subject alternative name of type %v is required", p.Name, p.SANTypes)
	}
	return nil
}

// Subject returns the request's subject reduced to the attributes the
// profile copies, or an error naming the first attribute it does not. A
// subject with nothing left, on a profile that requires no SAN, is
// refused too: the certificate would name nothing.
func (p *Profile) Subject(requested pkix.Name) (pkix.Name, error) {
	allowed := make(map[string]bool, len(p.SubjectRDNs))
	for _, rdn := range p.SubjectRDNs {
		allowed[rdn] = true
	}
	// Names carries every attribute the request encoded, including the
	// ones pkix.Name has no field for. Walking it rather than the fields
	// is what makes an unknown attribute visible.
	var kept []pkix.AttributeTypeAndValue
	for _, atv := range requested.Names {
		short, known := rdnShortName(atv.Type)
		if !known {
			return pkix.Name{}, fmt.Errorf("profile %q: subject attribute %s is not one this CA issues", p.Name, atv.Type)
		}
		if !allowed[short] {
			return pkix.Name{}, fmt.Errorf("profile %q: subject attribute %s is not allowed (want only %v)", p.Name, short, p.SubjectRDNs)
		}
		kept = append(kept, atv)
	}
	var out pkix.Name
	out.FillFromRDNSequence(&pkix.RDNSequence{kept})
	if len(kept) == 0 && !p.SANRequired {
		return pkix.Name{}, fmt.Errorf("profile %q: the request's subject carries none of %v and the profile requires no subject alternative name", p.Name, p.SubjectRDNs)
	}
	return out, nil
}

// rdnOIDs maps the short names a profile uses to the attribute types.
var rdnOIDs = map[string]asn1.ObjectIdentifier{
	"CN": {2, 5, 4, 3},
	"O":  {2, 5, 4, 10},
	"OU": {2, 5, 4, 11},
	"C":  {2, 5, 4, 6},
	"ST": {2, 5, 4, 8},
	"L":  {2, 5, 4, 7},
}

func rdnShortName(oid asn1.ObjectIdentifier) (string, bool) {
	for name, o := range rdnOIDs {
		if o.Equal(oid) {
			return name, true
		}
	}
	return "", false
}

func rdnNames() string {
	names := make([]string, 0, len(rdnOIDs))
	for n := range rdnOIDs {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// The vocabulary a configured profile is written in. Each name maps to
// exactly one value, and a name outside the map is refused at load, so a
// typo cannot become a silently narrower or wider certificate.
var (
	extKeyUsageNames = map[string]x509.ExtKeyUsage{
		"serverAuth":      x509.ExtKeyUsageServerAuth,
		"clientAuth":      x509.ExtKeyUsageClientAuth,
		"codeSigning":     x509.ExtKeyUsageCodeSigning,
		"emailProtection": x509.ExtKeyUsageEmailProtection,
		"timeStamping":    x509.ExtKeyUsageTimeStamping,
		"ocspSigning":     x509.ExtKeyUsageOCSPSigning,
	}
	keyUsageNames = map[string]x509.KeyUsage{
		"digitalSignature":  x509.KeyUsageDigitalSignature,
		"contentCommitment": x509.KeyUsageContentCommitment,
		"keyEncipherment":   x509.KeyUsageKeyEncipherment,
		"keyAgreement":      x509.KeyUsageKeyAgreement,
	}
	sanTypeNames = map[string]SANType{
		"dns": SANDNS, "ip": SANIP, "uri": SANURI, "email": SANEmail,
	}
	keyAlgorithmNames = map[string]KeyAlgorithm{
		"ec-p256": KeyECP256, "ec-p384": KeyECP384, "ec-p521": KeyECP521, "rsa": KeyRSA,
	}
)

// Spec is a profile as written in configuration. Every list is a list of
// names from the vocabulary above.
type Spec struct {
	ExtendedKeyUsages []string `yaml:"extended_key_usages"`
	KeyUsages         []string `yaml:"key_usages"`
	SANTypes          []string `yaml:"san_types"`
	SANRequired       bool     `yaml:"san_required"`
	Subject           []string `yaml:"subject"`
	KeyAlgorithms     []string `yaml:"key_algorithms"`
	ValidityHours     int      `yaml:"validity_hours"`
	OCSPNoCheck       bool     `yaml:"ocsp_no_check"`
}

// Compile turns a Spec into a Profile named name, refusing any name the
// vocabulary does not carry. It does not Validate; Set.Validate does,
// with the ceiling.
func (s Spec) Compile(name string) (*Profile, error) {
	p := &Profile{Name: name, SANRequired: s.SANRequired, OCSPNoCheck: s.OCSPNoCheck, Validity: time.Duration(s.ValidityHours) * time.Hour}
	for _, n := range s.ExtendedKeyUsages {
		v, ok := extKeyUsageNames[n]
		if !ok {
			return nil, fmt.Errorf("profile %q: unknown extended key usage %q (want one of %s)", name, n, sortedKeys(extKeyUsageNames))
		}
		p.ExtKeyUsages = append(p.ExtKeyUsages, v)
	}
	for _, n := range s.KeyUsages {
		v, ok := keyUsageNames[n]
		if !ok {
			return nil, fmt.Errorf("profile %q: unknown key usage %q (want one of %s)", name, n, sortedKeys(keyUsageNames))
		}
		p.KeyUsage |= v
	}
	for _, n := range s.SANTypes {
		v, ok := sanTypeNames[n]
		if !ok {
			return nil, fmt.Errorf("profile %q: unknown san type %q (want one of %s)", name, n, sortedKeys(sanTypeNames))
		}
		p.SANTypes = append(p.SANTypes, v)
	}
	for _, n := range s.KeyAlgorithms {
		v, ok := keyAlgorithmNames[n]
		if !ok {
			return nil, fmt.Errorf("profile %q: unknown key algorithm %q (want one of %s)", name, n, sortedKeys(keyAlgorithmNames))
		}
		p.KeyAlgorithms = append(p.KeyAlgorithms, v)
	}
	p.SubjectRDNs = append(p.SubjectRDNs, s.Subject...)
	return p, nil
}

// Parse compiles a configured set. An empty map is an error here rather
// than a fall-through to Builtin: the caller decides what an absent
// section means, and a present-but-empty one means the operator wrote
// nothing usable.
func Parse(specs map[string]Spec) (Set, error) {
	if len(specs) == 0 {
		return nil, errors.New("profile: the profiles section is present but empty")
	}
	set := make(Set, len(specs))
	for name, spec := range specs {
		if strings.TrimSpace(name) == "" {
			return nil, errors.New("profile: a profile has an empty name")
		}
		p, err := spec.Compile(name)
		if err != nil {
			return nil, err
		}
		set[name] = p
	}
	return set, nil
}

func sortedKeys[V any](m map[string]V) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// Builtin returns the four profiles the platform ships with, as a fresh
// set each call so a caller may adjust one without changing the others.
//
//   - tls-server: what a service presents. serverAuth, at least one DNS
//     or IP name, ninety days.
//   - tls-client: what a client authenticates with, including this CA's
//     own operators. clientAuth, an optional URI or email name, a subject
//     of CN, O and OU, ninety days.
//   - code-signing: what signs a release. codeSigning, CN and O, a year.
//   - ocsp-responder: the delegated responder. ocspSigning with
//     id-pkix-ocsp-nocheck, seven days, because nocheck means the
//     certificate cannot meaningfully be revoked and its lifetime is the
//     only limit on a compromised key.
//
// keyEncipherment appears on the TLS profiles for RSA keys, which may be
// asked to do RSA key transport under TLS 1.2; an EC key never carries it.
func Builtin() Set {
	allKeys := []KeyAlgorithm{KeyECP256, KeyECP384, KeyECP521, KeyRSA}
	return Set{
		"tls-server": {
			Name:          "tls-server",
			ExtKeyUsages:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			KeyUsage:      x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			SANTypes:      []SANType{SANDNS, SANIP},
			SANRequired:   true,
			SubjectRDNs:   []string{"CN"},
			KeyAlgorithms: allKeys,
			Validity:      90 * 24 * time.Hour,
		},
		"tls-client": {
			Name:          "tls-client",
			ExtKeyUsages:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			KeyUsage:      x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			SANTypes:      []SANType{SANURI, SANEmail},
			SubjectRDNs:   []string{"CN", "O", "OU"},
			KeyAlgorithms: allKeys,
			Validity:      90 * 24 * time.Hour,
		},
		"code-signing": {
			Name:          "code-signing",
			ExtKeyUsages:  []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning},
			KeyUsage:      x509.KeyUsageDigitalSignature,
			SANTypes:      []SANType{SANURI},
			SubjectRDNs:   []string{"CN", "O"},
			KeyAlgorithms: allKeys,
			Validity:      365 * 24 * time.Hour,
		},
		"ocsp-responder": {
			Name:          "ocsp-responder",
			ExtKeyUsages:  []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
			KeyUsage:      x509.KeyUsageDigitalSignature,
			SubjectRDNs:   []string{"CN"},
			KeyAlgorithms: []KeyAlgorithm{KeyECP256, KeyECP384, KeyECP521},
			Validity:      7 * 24 * time.Hour,
			OCSPNoCheck:   true,
		},
	}
}
