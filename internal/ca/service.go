package ca

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// ServiceCertificateParams configures LoadServiceCertificate.
type ServiceCertificateParams struct {
	// KeyLabel is the CKA_LABEL of the service's TLS key pair, on the same
	// token as the intermediate. It is never the intermediate's own label:
	// a key that signs certificates must not also sign TLS handshakes,
	// where the bytes signed are chosen by whoever connects.
	KeyLabel string
	// CertPath is the service's TLS certificate, PEM, one certificate: a
	// leaf this CA issued over the key under KeyLabel.
	CertPath string
	Curve    pk11.ECCurve
}

// ErrNotAServiceCertificate is returned by LoadServiceCertificate for a
// certificate that cannot serve as the service's TLS identity.
var ErrNotAServiceCertificate = fmt.Errorf("ca: certificate is not a valid TLS identity for this service")

// LoadServiceCertificate loads the certificate the service presents on
// its authenticated listener, over the HSM-held key it belongs to. The
// private key never leaves the token: the returned tls.Certificate signs
// each handshake through the same crypto.Signer the CA signs
// certificates with.
//
// The certificate is checked before it is served. It must be a leaf,
// not a CA; it must assert the serverAuth extended key usage; it must be
// inside its validity window; the issuer must have signed it, so the
// chain the service presents (leaf, then issuer) verifies to the root a
// client holds; and its public key must match the token key under
// KeyLabel. The token is expected to be logged in already: the service
// loads the intermediate first, and this key lives beside it.
func LoadServiceCertificate(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, sessionOpts pk11.SessionOptions, issuer *x509.Certificate, params ServiceCertificateParams) (tls.Certificate, error) {
	if issuer == nil {
		return tls.Certificate{}, fmt.Errorf("%w: no issuer certificate to check the chain against", ErrNotAServiceCertificate)
	}
	leaf, err := loadCertPEM(params.CertPath)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := checkServiceCert(leaf, issuer, params.CertPath); err != nil {
		return tls.Certificate{}, err
	}

	signer, err := NewSigner(ctx, adapter, ws, sessionOpts, params.KeyLabel, params.Curve)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("ca: loading the service TLS key %q: %w", params.KeyLabel, err)
	}
	if err := checkKeyMatchesCert(signer, leaf, params.KeyLabel, params.CertPath); err != nil {
		return tls.Certificate{}, err
	}

	return tls.Certificate{
		// Leaf first, then the issuer, the order TLS sends a chain in. The
		// root is the client's trust anchor and is not sent.
		Certificate: [][]byte{leaf.Raw, issuer.Raw},
		PrivateKey:  signer,
		Leaf:        leaf,
	}, nil
}

// checkServiceCert enforces the constraints described on
// LoadServiceCertificate.
func checkServiceCert(leaf, issuer *x509.Certificate, path string) error {
	if leaf.IsCA {
		return fmt.Errorf("%w: %s is a CA certificate; the service's TLS identity is a leaf, and a CA certificate presented in a handshake would be an issuing key signing attacker-chosen bytes",
			ErrNotAServiceCertificate, path)
	}
	serverAuth := false
	for _, eku := range leaf.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			serverAuth = true
		}
	}
	if !serverAuth {
		return fmt.Errorf("%w: %s does not assert the serverAuth extended key usage, so a client refuses it as a server certificate",
			ErrNotAServiceCertificate, path)
	}
	now := time.Now()
	if now.Before(leaf.NotBefore) {
		return fmt.Errorf("%w: %s is not valid until %s", ErrIssuerNotValid, path, leaf.NotBefore.Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return fmt.Errorf("%w: %s expired at %s", ErrIssuerNotValid, path, leaf.NotAfter.Format(time.RFC3339))
	}
	// Checked by verifying the signature, not by comparing names.
	if err := leaf.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("%w: %s was not signed by the loaded intermediate %q, so the chain the service would present does not verify: %v",
			ErrNotAServiceCertificate, path, issuer.Subject.CommonName, err)
	}
	return nil
}
