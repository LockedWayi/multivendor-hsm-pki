package ca

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// LoadIntermediateParams configures LoadIntermediate. Nothing here names
// the root's token, workspace or key label, and nothing may. The service
// holds the intermediate only.
type LoadIntermediateParams struct {
	// KeyLabel is the CKA_LABEL of the intermediate's key pair on the token
	// this service authenticates.
	KeyLabel string
	// CertPath is the ceremony-produced intermediate certificate, PEM. It
	// holds no private key material.
	CertPath string
	Curve    pk11.ECCurve
	// CertTTL is the validity window Issue gives every leaf this CA signs.
	CertTTL time.Duration
	// Distribution is where the leaves this CA issues point relying parties
	// for revocation status and for the issuing certificate. Unlike the
	// intermediate's own CDP and AIA, fixed at ceremony time, these follow
	// the service's configured base URL.
	Distribution LeafDistribution
}

// LoadIntermediate authenticates the token and loads an existing,
// ceremony-produced intermediate. It creates nothing: a service that can
// mint its own CA is a service whose compromise yields a root. A missing
// key or certificate is a configuration error.
//
// The certificate is checked before the service comes up. It must be a CA
// certificate, must not be self-signed (that would put a root online),
// must carry pathlen:0, must assert keyCertSign and cRLSign, must be inside
// its validity window, and its public key must match the token key under
// KeyLabel. params.Distribution is checked first: a CA with no
// distribution point issues nothing.
func LoadIntermediate(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, sessionOpts pk11.SessionOptions, resolvePIN PINResolver, params LoadIntermediateParams) (*CA, error) {
	// Checked before the token is touched. A service that starts and then
	// refuses every issuance has failed in the wrong place.
	if err := params.Distribution.Validate(); err != nil {
		return nil, fmt.Errorf("ca: leaf distribution: %w", err)
	}
	if !adapter.TokenLoggedIn() {
		pin, err := resolvePIN()
		if err != nil {
			return nil, fmt.Errorf("ca: resolving PIN: %w", err)
		}
		if err := adapter.LoginToken(ctx, ws, pin, pk11.RoleUser); err != nil {
			return nil, fmt.Errorf("ca: token login: %w", err)
		}
	}

	cert, err := loadCertPEM(params.CertPath)
	if err != nil {
		return nil, err
	}
	if err := checkIntermediateCert(cert, params.CertPath); err != nil {
		return nil, err
	}

	signer, err := NewSigner(ctx, adapter, ws, sessionOpts, params.KeyLabel, params.Curve)
	if err != nil {
		return nil, fmt.Errorf("ca: loading intermediate key %q: %w", params.KeyLabel, err)
	}
	if err := checkKeyMatchesCert(signer, cert, params.KeyLabel, params.CertPath); err != nil {
		return nil, err
	}

	return &CA{cert: cert, signer: signer, certTTL: params.CertTTL, dist: params.Distribution}, nil
}

// checkIntermediateCert enforces the tier constraints described on
// LoadIntermediate.
func checkIntermediateCert(cert *x509.Certificate, path string) error {
	// crypto/x509 leaves IsCA and MaxPathLenZero at zero when the extension
	// is absent, so the extension's presence is checked first.
	if !cert.BasicConstraintsValid {
		return fmt.Errorf("%w: %s carries no basicConstraints extension, so it asserts no CA status at all (RFC 5280 §4.2.1.9)",
			ErrNotAnIntermediate, path)
	}
	if !cert.IsCA {
		return fmt.Errorf("%w: %s is not a CA certificate (IsCA=false)", ErrNotAnIntermediate, path)
	}
	// A self-signed certificate verifies under its own key. Subject and
	// Issuer are operator-controlled strings and say nothing about who
	// signed.
	if err := cert.CheckSignatureFrom(cert); err == nil {
		return fmt.Errorf("%w: %s is self-signed, which means it is a root; this service holds the intermediate only, and the root must stay offline",
			ErrRootCertificateRejected, path)
	}
	if !cert.MaxPathLenZero {
		return fmt.Errorf("%w: %s does not carry pathlen:0, so it is permitted to certify further CAs; this platform's hierarchy is two tiers",
			ErrNotAnIntermediate, path)
	}
	// A compliant verifier enforces keyUsage independently of
	// basicConstraints (RFC 5280 §4.2.1.3). This service signs certificates
	// and a CRL, so both bits are required.
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("%w: %s does not assert the keyCertSign key usage, so every certificate signed under it is rejected by a compliant verifier (RFC 5280 §4.2.1.3)",
			ErrNotAnIntermediate, path)
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return fmt.Errorf("%w: %s does not assert the cRLSign key usage, and this service publishes the CRL covering the certificates it issues (GET /crl)",
			ErrNotAnIntermediate, path)
	}
	// RFC 5280 §6.1.3 validates every certificate in the path at the same
	// instant. Issue checks again per issuance: a service that started
	// before the expiry is still running after it.
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("%w: %s is not valid until %s", ErrIssuerNotValid, path, cert.NotBefore.Format(time.RFC3339))
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("%w: %s expired at %s", ErrIssuerNotValid, path, cert.NotAfter.Format(time.RFC3339))
	}
	return nil
}

// checkKeyMatchesCert confirms the HSM key the service will sign with is the
// one the loaded certificate belongs to.
func checkKeyMatchesCert(signer *Signer, cert *x509.Certificate, keyLabel, certPath string) error {
	certPub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: %s carries a %T public key; this CA signs with ECDSA keys only",
			ErrKeyCertMismatch, certPath, cert.PublicKey)
	}
	signerPub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("%w: HSM key %q is %T, not ECDSA", ErrKeyCertMismatch, keyLabel, signer.Public())
	}
	if !certPub.Equal(signerPub) {
		return fmt.Errorf("%w: HSM key %q is not the key certified by %s; the service would sign with a key the certificate does not attest to",
			ErrKeyCertMismatch, keyLabel, certPath)
	}
	return nil
}

// loadCertPEM reads the single PEM certificate at path. A file with a
// second block is rejected: an operator pasting a chain into
// ca.intermediate_cert_path would otherwise get whichever block came first.
func loadCertPEM(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ca: reading CA certificate %s: %w", path, err)
	}
	block, rest := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("ca: %s does not contain a PEM block", path)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("ca: %s contains more than one PEM block; it must hold exactly one certificate, not a chain", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing CA certificate %s: %w", path, err)
	}
	return cert, nil
}
