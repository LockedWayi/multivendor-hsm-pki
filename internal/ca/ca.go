package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SKI is a non-cryptographic identifier hint (RFC 5280 §4.2.1.2 method 1), not a security boundary.
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net/url"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/profile"
)

// minRSAKeyBits is the smallest RSA modulus this CA signs a CSR for. 2048
// bits is the floor NIST and the CA/Browser Forum accept. The CA's own key
// is ECDSA; clients need not match. profile.MinRSAKeyBits is the same
// number, and TestKeyUsageFor_CoversEveryAllowedKeyType pins the two.
const minRSAKeyBits = profile.MinRSAKeyBits

// issuanceClockSkewAllowance backdates a leaf's NotBefore so a verifier
// whose clock trails this host's does not reject a certificate as
// not-yet-valid. internal/api applies the same allowance to a CRL's
// thisUpdate, and the ceremony to the certificates and CRL it signs.
const issuanceClockSkewAllowance = 5 * time.Minute

// LeafDistribution is the set of URLs Issue writes into every leaf: where
// the leaf's CRL is published, where the issuing certificate can be
// fetched, and, when a responder exists, where its status can be asked.
// The first two are required. An extension is fixed at signature time,
// so a leaf issued without a distribution point can never gain one.
//
// OCSPURL is optional and is set only when a responder is running: a
// certificate naming a responder that does not answer fails closed at a
// verifier that requires OCSP, which is worse than naming none. A leaf
// issued before the responder existed never carries it.
type LeafDistribution struct {
	// CRLURL is the leaf's CRL distribution point, this service's own /crl.
	// The root's CRL covers the intermediate and is named in the
	// intermediate's own certificate.
	CRLURL string
	// IssuerCertURL is the AIA CA-Issuers pointer, where a relying party
	// holding only the leaf fetches the intermediate that signed it.
	IssuerCertURL string
	// OCSPURL is the AIA OCSP pointer, this service's own /ocsp, or empty
	// when no responder is configured.
	OCSPURL string
}

// Validate reports whether both distribution URLs are present and fetchable
// in principle.
func (d LeafDistribution) Validate() error {
	if err := ValidateDistributionURL("CRL distribution point", d.CRLURL); err != nil {
		return err
	}
	if err := ValidateDistributionURL("AIA CA-Issuers URL", d.IssuerCertURL); err != nil {
		return err
	}
	if d.OCSPURL != "" {
		return ValidateDistributionURL("AIA OCSP URL", d.OCSPURL)
	}
	return nil
}

// ValidateDistributionURL rejects a URL that would be written into a
// certificate. Only http and https are accepted; RFC 5280 §4.2.1.13 names
// HTTP as the baseline for CRL distribution points. field names the
// setting, so the caller's own name appears in the error.
func ValidateDistributionURL(field, raw string) error {
	if raw == "" {
		return fmt.Errorf("%s is not set", field)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s is not a valid URL: %w", field, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s must be an http or https URL, got scheme %q", field, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%s has no host: %q", field, raw)
	}
	return nil
}

// CA issues and revokes X.509 certificates under one issuer certificate,
// signing through an HSM-backed crypto.Signer. It never holds the issuer's
// private key.
type CA struct {
	cert   *x509.Certificate
	signer crypto.Signer
	// maxTTL is the longest validity any profile may grant. A profile is
	// policy an operator wrote; the ceiling is the one number the CA
	// enforces over every profile, and it is checked at the point of use
	// rather than only at startup.
	maxTTL time.Duration
	dist   LeafDistribution
}

// NewCA builds a CA from a certificate and signer the caller already
// validated. LoadIntermediate is the checked path the service uses;
// RunCeremony and tests use this one. maxTTL caps every profile's
// validity. dist may be zero for a CA that only builds CRLs; Issue
// validates it at the point of use.
func NewCA(cert *x509.Certificate, signer crypto.Signer, maxTTL time.Duration, dist LeafDistribution) *CA {
	return &CA{cert: cert, signer: signer, maxTTL: maxTTL, dist: dist}
}

// Certificate returns the CA's own issuer certificate.
func (c *CA) Certificate() *x509.Certificate {
	return c.cert
}

// Issue validates csr against p and, if it passes, signs a new leaf
// certificate under the CA's issuer certificate. The template is filled
// from the profile and from nothing else: the request supplies a public
// key, a subject the profile filters, and names of the types the profile
// allows. A malformed, badly-signed, or out-of-policy request is refused
// rather than partially honoured, and a nil profile is refused too; there
// is no default.
func (c *CA) Issue(csr *x509.CertificateRequest, p *profile.Profile) (*x509.Certificate, error) {
	// The CA's own distribution URLs are checked before the CSR. A CA with
	// nowhere to publish revocation does not issue.
	if err := c.dist.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoDistributionPoints, err)
	}
	if p == nil {
		return nil, fmt.Errorf("%w: Issue called with no profile", profile.ErrUnknownProfile)
	}
	if err := validateCSR(csr); err != nil {
		return nil, err
	}
	// The policy checks, in the order a caller can fix them: the key they
	// generated, the names they asked for, the subject they wrote.
	if err := p.AllowsKey(csr.PublicKey); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrDisallowedKeyType, err)
	}
	if err := p.CheckSANs(csr); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNameNotAllowed, err)
	}
	subject, err := p.Subject(csr.Subject)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSubjectNotAllowed, err)
	}
	// The ceiling is checked here as well as at startup: the profile set
	// is configuration, and configuration is validated once, while this
	// runs on every request.
	if c.maxTTL > 0 && p.Validity > c.maxTTL {
		return nil, fmt.Errorf("%w: profile %q grants %s, the CA's ceiling is %s", ErrValidityExceedsPolicy, p.Name, p.Validity, c.maxTTL)
	}

	now := time.Now()
	// NotBefore is backdated for clock skew. Both ends of the window are
	// checked against the issuer before anything is signed.
	notBefore := now.Add(-issuanceClockSkewAllowance)
	notAfter := now.Add(p.Validity)
	if err := c.checkIssuerCanCover(now, notAfter); err != nil {
		return nil, err
	}

	serial, err := GenerateSerial()
	if err != nil {
		return nil, err
	}
	ski, err := subjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsageFor(csr.PublicKey, p.KeyUsage),
		ExtKeyUsage:           append([]x509.ExtKeyUsage(nil), p.ExtKeyUsages...),
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          ski,
		AuthorityKeyId:        c.cert.SubjectKeyId,
		// CheckSANs has already refused any type the profile does not
		// allow, so what is copied here is exactly what was allowed.
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,
		// All of them point at this service. OCSPServer is set only when
		// a responder is configured; see LeafDistribution.
		CRLDistributionPoints: []string{c.dist.CRLURL},
		IssuingCertificateURL: []string{c.dist.IssuerCertURL},
	}
	if c.dist.OCSPURL != "" {
		template.OCSPServer = []string{c.dist.OCSPURL}
	}
	if p.OCSPNoCheck {
		// id-pkix-ocsp-nocheck is a NULL (RFC 6960 §4.2.2.2.1): DER 05 00.
		template.ExtraExtensions = append(template.ExtraExtensions, pkix.Extension{
			Id:    profile.OIDOCSPNoCheck,
			Value: []byte{0x05, 0x00},
		})
	}

	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, csr.PublicKey, c.signer)
	if err != nil {
		return nil, fmt.Errorf("ca: CreateCertificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// checkIssuerCanCover refuses to sign what the issuing certificate cannot
// vouch for now. Two cases: the issuer is outside its own validity window
// (RFC 5280 §6.1.3 validates every certificate in a path at the same
// instant), or the leaf would outlive the issuer.
//
// The leaf is refused, not clamped to the issuer's NotAfter. A clamped
// certificate has a lifetime that differs from the configured one, and the
// holder finds out at renewal time. So a service with ca.cert_ttl_hours = N
// stops issuing N hours before its intermediate expires. The remedy is to
// re-issue the intermediate.
func (c *CA) checkIssuerCanCover(now, notAfter time.Time) error {
	if now.Before(c.cert.NotBefore) {
		return fmt.Errorf("%w: issuer %q is not valid until %s",
			ErrIssuerNotValid, c.cert.Subject.CommonName, c.cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(c.cert.NotAfter) {
		return fmt.Errorf("%w: issuer %q expired at %s",
			ErrIssuerNotValid, c.cert.Subject.CommonName, c.cert.NotAfter.Format(time.RFC3339))
	}
	if notAfter.After(c.cert.NotAfter) {
		return fmt.Errorf("%w: a leaf valid until %s would outlive issuer %q, which expires at %s; reduce ca.cert_ttl_hours or re-issue the intermediate",
			ErrValidityExceedsIssuer, notAfter.Format(time.RFC3339),
			c.cert.Subject.CommonName, c.cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// validateCSR checks a CSR's self-signature, subject and key type. Each
// rejection is a distinct sentinel error so the HTTP layer can map it to a
// 4xx response.
func validateCSR(csr *x509.CertificateRequest) error {
	if err := csr.CheckSignature(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCSRSignature, err)
	}
	if csr.Subject.CommonName == "" && len(csr.Subject.Organization) == 0 {
		return ErrEmptySubject
	}
	switch pub := csr.PublicKey.(type) {
	case *ecdsa.PublicKey:
		switch pub.Curve.Params().Name {
		case "P-256", "P-384", "P-521":
		default:
			return fmt.Errorf("%w: EC curve %s", ErrDisallowedKeyType, pub.Curve.Params().Name)
		}
	case *rsa.PublicKey:
		if pub.N.BitLen() < minRSAKeyBits {
			return fmt.Errorf("%w: RSA key is %d bits, want >= %d", ErrDisallowedKeyType, pub.N.BitLen(), minRSAKeyBits)
		}
	default:
		return fmt.Errorf("%w: %T", ErrDisallowedKeyType, csr.PublicKey)
	}
	return nil
}

// keyUsageFor narrows a profile's key usage to what the subject's key
// algorithm can do. keyEncipherment is an RSA operation (RFC 5480 §3), so
// an ECDSA certificate never carries it whatever the profile lists; the
// profile's set is the most any certificate under it asserts.
func keyUsageFor(pub crypto.PublicKey, fromProfile x509.KeyUsage) x509.KeyUsage {
	switch pub.(type) {
	case *rsa.PublicKey:
		return fromProfile
	case *ecdsa.PublicKey:
		return fromProfile &^ x509.KeyUsageKeyEncipherment
	default:
		// Unreachable: validateCSR allows only the two types above. The
		// narrowest reading is returned, so widening validateCSR grants
		// nothing here by default. TestKeyUsageFor_CoversEveryAllowedKeyType
		// pins the two lists together.
		return fromProfile &^ x509.KeyUsageKeyEncipherment
	}
}

// GenerateSerial returns a new serial number: 128 bits from crypto/rand,
// above the 64-bit floor and never sequential.
func GenerateSerial() (*big.Int, error) {
	// RFC 5280 §4.1.2.2 requires a positive serial, and an all-zero draw
	// gives zero. Redraw instead of asserting it cannot happen. The top bit
	// is not forced: that would cost a bit of entropy and add a DER padding
	// octet for no gain.
	for {
		buf := make([]byte, 16)
		if _, err := rand.Read(buf); err != nil {
			return nil, fmt.Errorf("ca: generating serial: %w", err)
		}
		if serial := new(big.Int).SetBytes(buf); serial.Sign() > 0 {
			return serial, nil
		}
	}
}

// subjectKeyID computes an RFC 5280 §4.2.1.2 method 1 key identifier:
// SHA-1 over the SubjectPublicKeyInfo. It is a hint for path building, not
// a security boundary.
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ca: marshaling public key for SubjectKeyId: %w", err)
	}
	// SHA-1 is what RFC 5280 §4.2.1.2 method 1 names; nothing is authenticated by it.
	// nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1
	sum := sha1.Sum(der)
	return sum[:], nil
}
