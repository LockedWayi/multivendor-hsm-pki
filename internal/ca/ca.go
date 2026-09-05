package ca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // SKI is a non-cryptographic identifier hint (RFC 5280 §4.2.1.2 method 1), not a security boundary.
	"crypto/x509"
	"fmt"
	"math/big"
	"net/url"
	"time"
)

// minRSAKeyBits is the smallest RSA modulus this CA will sign a CSR for.
// 2048 bits is the floor NIST and the CA/Browser Forum both still treat as
// acceptable; the CA's own key is ECDSA, but clients are
// not required to match that choice.
const minRSAKeyBits = 2048

// issuanceClockSkewAllowance backdates a leaf's NotBefore so a verifier
// whose clock trails this host's does not reject a certificate as
// not-yet-valid. internal/api applies the same allowance to a CRL's
// thisUpdate, and the ceremony to the certificates and CRL it signs.
const issuanceClockSkewAllowance = 5 * time.Minute

// LeafDistribution is the pair of URLs Issue writes into every leaf
// certificate: where the CRL that governs the leaf is published, and where
// the certificate that signed it can be fetched.
//
// Both are required, and Issue refuses to sign without them. The reason is
// the same one that makes the ceremony's own URLs required (CeremonyParams):
// an extension is fixed at signature time. A leaf issued today without a
// distribution point can never gain one — it can only be revoked and
// replaced — so "we will add it later" is not a thing this CA can do, and
// the failure would surface at a relying party that cannot check revocation
// rather than here.
//
// Note the absence of an OCSP field. It is deliberate and stays until the
// responder exists (Phase 5b): a certificate that names an OCSP responder
// which is not there is worse than one that names none, because a verifier
// configured to require OCSP will fail closed against a URL that was never
// going to answer.
type LeafDistribution struct {
	// CRLURL is the leaf's CRL distribution point — this service's own
	// /crl, which covers the leaves this intermediate issued. It is not the
	// root's CRL: that one covers the intermediate and is named in the
	// intermediate's certificate instead.
	CRLURL string
	// IssuerCertURL is the AIA CA-Issuers pointer: where a relying party
	// holding only the leaf can fetch the intermediate that signed it and
	// continue building the path upward.
	IssuerCertURL string
}

// Validate reports whether both distribution URLs are present and fetchable
// in principle.
func (d LeafDistribution) Validate() error {
	if err := ValidateDistributionURL("CRL distribution point", d.CRLURL); err != nil {
		return err
	}
	return ValidateDistributionURL("AIA CA-Issuers URL", d.IssuerCertURL)
}

// ValidateDistributionURL rejects a URL that would be embedded into a
// certificate whose extensions cannot be edited afterward. Only http and
// https are accepted: RFC 5280 §4.2.1.13 names HTTP as the interop baseline
// for CRL distribution points, and a scheme a relying party cannot fetch is
// the same as no distribution point at all.
//
// field names the setting being checked, so the caller's own vocabulary
// ("RootCRLURL", "ca.base_url") appears in the error rather than this
// function's. Callers add their own package prefix.
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

// CA issues, and will (sub-task 2.5) revoke, X.509 certificates under one
// issuer certificate, signing through an HSM-backed crypto.Signer. It never
// holds the issuer's private key itself.
type CA struct {
	cert    *x509.Certificate
	signer  crypto.Signer
	certTTL time.Duration
	dist    LeafDistribution
}

// NewCA constructs a CA from an issuer certificate and signer a caller
// already holds.
//
// LoadIntermediate is what the service itself uses: it reads the certificate
// from disk and enforces the tier constraints (CA, not self-signed,
// pathlen:0, key matches certificate) before building anything. This is the
// unchecked constructor beneath it, for callers that obtained a validated
// pair some other way — chiefly RunCeremony, which has the certificate it
// just signed in hand, and tests. It performs no validation of its own, so
// prefer LoadIntermediate anywhere the input came from configuration.
//
// dist may be left zero for a CA that will only build CRLs and never issue:
// Issue validates it at the point of use rather than here, so a CRL-only
// caller is not forced to invent URLs it has no use for.
func NewCA(cert *x509.Certificate, signer crypto.Signer, certTTL time.Duration, dist LeafDistribution) *CA {
	return &CA{cert: cert, signer: signer, certTTL: certTTL, dist: dist}
}

// Certificate returns the CA's own issuer certificate.
func (c *CA) Certificate() *x509.Certificate {
	return c.cert
}

// Issue validates csr and, if it passes, signs a new leaf certificate under
// the CA's issuer certificate. A malformed, unparseable, or badly-signed
// CSR is rejected rather than partially processed.
func (c *CA) Issue(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	// Checked before the CSR, because this is a statement about this CA
	// rather than about the request: a CA with nowhere to publish
	// revocation for what it signs does not issue at all. The alternative —
	// sign it and omit the extension — produces a certificate whose
	// revocation no relying party can ever discover, and there is no later
	// point at which that can be repaired.
	if err := c.dist.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrNoDistributionPoints, err)
	}
	if err := validateCSR(csr); err != nil {
		return nil, err
	}

	now := time.Now()
	// NotBefore is backdated to absorb clock skew, so the window this leaf
	// will claim is [now-skew, now+certTTL]. Both ends are checked against
	// the issuer before anything is signed.
	notBefore := now.Add(-issuanceClockSkewAllowance)
	notAfter := now.Add(c.certTTL)
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
		Subject:               csr.Subject,
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsageFor(csr.PublicKey),
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SubjectKeyId:          ski,
		AuthorityKeyId:        c.cert.SubjectKeyId,
		DNSNames:              csr.DNSNames,
		IPAddresses:           csr.IPAddresses,
		EmailAddresses:        csr.EmailAddresses,
		URIs:                  csr.URIs,
		// Where this leaf's revocation status is published, and where the
		// certificate that signed it can be fetched. Both point at this
		// service (internal/api serves them), so they resolve for anyone who
		// can reach the CA at all. No OCSPServer is set — see
		// LeafDistribution for why an absent responder gets no pointer.
		CRLDistributionPoints: []string{c.dist.CRLURL},
		IssuingCertificateURL: []string{c.dist.IssuerCertURL},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, csr.PublicKey, c.signer)
	if err != nil {
		return nil, fmt.Errorf("ca: CreateCertificate: %w", err)
	}
	return x509.ParseCertificate(der)
}

// checkIssuerCanCover refuses to sign anything the issuing certificate
// cannot actually vouch for at the moment of issuance.
//
// Two distinct failures, both fail-closed:
//
//   - The issuer is outside its own validity window. RFC 5280 §6.1.3
//     validates every certificate in a path against the same instant, so a
//     leaf signed by an expired issuer is invalid the moment it exists.
//     Handing one to a caller who then deploys it is worse than refusing:
//     the failure surfaces at whatever tries to use it, far from the cause.
//   - The leaf would outlive the issuer. The certificate would advertise a
//     NotAfter the chain cannot honor, and stop working when the issuer
//     expires regardless of what it claims.
//
// # Rejected rather than clamped to the issuer's NotAfter
//
// This is the same choice, for the same reason, that the ceremony makes
// when an intermediate would outlive its root (CeremonyParams.validate):
// clamping hands back a certificate whose lifetime silently differs from
// the configured one, and the holder discovers it at renewal time — or
// does not, and is surprised by an early expiry.
//
// The operational consequence is deliberate and worth stating plainly: a
// service configured with ca.cert_ttl_hours = N stops issuing N hours
// before its intermediate expires, rather than quietly issuing
// ever-shorter certificates as that date approaches. The remedy is the one
// the platform already has — re-issue the intermediate from the root
// ceremony — and a loud, dated refusal is what prompts it.
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
		return fmt.Errorf("%w: a leaf valid until %s would outlive issuer %q, which expires at %s — reduce ca.cert_ttl_hours or re-issue the intermediate",
			ErrValidityExceedsIssuer, notAfter.Format(time.RFC3339),
			c.cert.Subject.CommonName, c.cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// validateCSR checks a CSR's self-signature, subject, and key type before
// Issue builds anything from it. Every rejection reason is a distinct
// sentinel error so a caller (the HTTP layer, sub-task 2.4) can map each to
// a specific 4xx response.
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

// keyUsageFor returns the key usages appropriate to the subject's key
// algorithm.
//
// keyEncipherment describes wrapping a symmetric key directly under the
// subject's public key, which is an RSA operation. An EC key cannot do it —
// ECDH-based key establishment is keyAgreement, a different bit — so
// asserting keyEncipherment on an ECDSA certificate states a capability the
// key does not have (RFC 5480 §3). Setting it unconditionally, as this did,
// was wrong for exactly the curve this CA issues by default.
func keyUsageFor(pub crypto.PublicKey) x509.KeyUsage {
	switch pub.(type) {
	case *rsa.PublicKey:
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	case *ecdsa.PublicKey:
		return x509.KeyUsageDigitalSignature
	default:
		// Unreachable: validateCSR runs first and allows only the two types
		// above. The case is spelled out anyway, and returns the narrowest
		// usage rather than a convenient one, so that widening
		// validateCSR's allow-list without revisiting this function grants
		// no capability by default. TestKeyUsageFor_CoversEveryAllowedKeyType
		// pins the two lists together.
		return x509.KeyUsageDigitalSignature
	}
}

// GenerateSerial returns a new certificate serial number: 128 bits of
// crypto/rand, well above the 64-bit floor and never sequential — a
// predictable serial weakens collision resistance across the CA's whole
// issued-certificate history, not just for one certificate.
func GenerateSerial() (*big.Int, error) {
	// RFC 5280 §4.1.2.2 requires a positive serial number, and SetBytes
	// yields zero for an all-zero draw. The probability is 2^-128, but
	// "cannot happen" and "must not be emitted" are different claims, and
	// only one of them is enforceable: redraw instead of asserting.
	//
	// Note what is deliberately NOT done here: forcing the top bit
	// (buf[0] |= 0x80) to guarantee a "full width" value. That would cost
	// a bit of entropy and force DER to prepend a 0x00 padding octet to
	// keep the INTEGER positive, making every serial 17 octets instead of
	// 16 — all to avoid a leading zero byte that is harmless. 128 random
	// bits is already double the 64-bit floor the phase file requires,
	// and stays comfortably above it even in the 1-in-256 case where the
	// top byte lands on zero.
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

// subjectKeyID computes an RFC 5280 §4.2.1.2 method-1-style key identifier:
// a SHA-1 hash, here of the marshaled SubjectPublicKeyInfo. This is a
// non-unique-guaranteed identifier hint used for certificate path building,
// not a security boundary, which is why SHA-1 remains an acceptable choice
// here despite being unfit for anything collision-resistance-dependent.
func subjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("ca: marshaling public key for SubjectKeyId: %w", err)
	}
	// The algorithm is named by RFC 5280 §4.2.1.2 method 1, not chosen
	// here, and the output is an identifier for path building rather than
	// a security decision: nothing is authenticated by it, and a collision
	// would produce a hint that fails to narrow a search, not a forged
	// certificate. Suppressed per rule and per line, so a SHA-1 used for
	// anything else in this file still fails the scan.
	// nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1
	sum := sha1.Sum(der)
	return sum[:], nil
}
