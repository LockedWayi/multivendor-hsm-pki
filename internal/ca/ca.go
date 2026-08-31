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
	"time"
)

// minRSAKeyBits is the smallest RSA modulus this CA will sign a CSR for.
// 2048 bits is the floor NIST and the CA/Browser Forum both still treat as
// acceptable; the CA's own key is ECDSA (CLAUDE.md §3.3), but clients are
// not required to match that choice.
const minRSAKeyBits = 2048

// CA issues, and will (sub-task 2.5) revoke, X.509 certificates under one
// issuer certificate, signing through an HSM-backed crypto.Signer. It never
// holds the issuer's private key itself (docs/phases/phase-2-ca-core.md).
type CA struct {
	cert    *x509.Certificate
	signer  crypto.Signer
	certTTL time.Duration
}

// Certificate returns the CA's own issuer certificate.
func (c *CA) Certificate() *x509.Certificate {
	return c.cert
}

// Issue validates csr and, if it passes, signs a new leaf certificate under
// the CA's issuer certificate. A malformed, unparseable, or badly-signed
// CSR is rejected rather than partially processed (CLAUDE.md §3.4).
func (c *CA) Issue(csr *x509.CertificateRequest) (*x509.Certificate, error) {
	if err := validateCSR(csr); err != nil {
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

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      csr.Subject,
		// A short backdate absorbs clock skew between this host and
		// whatever will validate the certificate first.
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(c.certTTL),
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
	}

	der, err := x509.CreateCertificate(rand.Reader, template, c.cert, csr.PublicKey, c.signer)
	if err != nil {
		return nil, fmt.Errorf("ca: CreateCertificate: %w", err)
	}
	return x509.ParseCertificate(der)
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
	default:
		// ECDSA, and anything else validateCSR has already allowed.
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
	sum := sha1.Sum(der)
	return sum[:], nil
}
