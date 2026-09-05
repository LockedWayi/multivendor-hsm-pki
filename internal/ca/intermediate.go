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

// LoadIntermediateParams configures LoadIntermediate.
//
// Note what is absent, and must stay absent: nothing here names the root's
// token, workspace, or key label. The service holds the intermediate and
// only the intermediate; the root exists solely inside the offline ceremony
// (RunCeremony) and is never reachable from a running server's configuration
type LoadIntermediateParams struct {
	// KeyLabel is the CKA_LABEL of the intermediate's key pair on the token
	// this service authenticates. The ceremony created it under a versioned
	// label.
	KeyLabel string
	// CertPath is the ceremony-produced intermediate certificate, PEM. It
	// contains no private key material — the intermediate's private key
	// never leaves the HSM.
	CertPath string
	Curve    pk11.ECCurve
	// CertTTL is the validity window Issue gives every leaf this CA signs.
	CertTTL time.Duration
	// Distribution is where the leaves this CA issues tell relying parties
	// to look for revocation status and for the issuing certificate. Unlike
	// the intermediate's own CDP and AIA — fixed by the root at ceremony
	// time — these are re-derived on every issuance, so they follow the
	// service's configured base URL (internal/config, internal/api.
	// LeafDistributionFor) rather than being frozen years earlier.
	Distribution LeafDistribution
}

// LoadIntermediate authenticates the token and loads an existing,
// ceremony-produced intermediate CA. It creates nothing.
//
// This replaced an earlier Bootstrap that would generate a key pair and
// self-sign a CA certificate when it found neither. That convenience is
// exactly what this phase removes: a service that can mint its own root is a
// service whose compromise yields a root. Provisioning now happens once, out
// of band, in a ceremony that runs on a token this service never names —
// so a missing key or certificate here is a configuration error to report,
// never a state to repair.
//
// The loaded certificate is checked before the service is allowed to come
// up, every check fail-closed:
//
//   - It must be a CA certificate. Signing leaves with a non-CA certificate
//     produces a chain no compliant verifier accepts.
//   - It must NOT be self-signed. A self-signed CA certificate here means
//     the operator has pointed the online service at a root, which is the
//     precise misconfiguration this phase exists to make impossible.
//   - It must carry pathlen:0. This platform's hierarchy is two tiers
//
// ; an online CA permitted to certify further CAs has a
//
//	  blast radius the design does not accept.
//	- It must assert keyCertSign and cRLSign. A compliant verifier enforces
//	  keyUsage independently of basicConstraints, so an intermediate
//	  missing either produces certificates or CRLs that are rejected
//	  everywhere but here.
//	- It must be inside its own validity window. Nothing an expired issuer
//	  signs can chain.
//	- Its public key must match the HSM key found under KeyLabel. Without
//	  this check, a certificate and a key label that refer to different key
//	  pairs would load cleanly and then produce signatures that verify
//	  against nothing — a failure that would surface at the relying party
//	  rather than at startup.
//
// params.Distribution is checked too, before anything else, because a CA
// that cannot name a distribution point issues nothing at all (see Issue).
func LoadIntermediate(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, sessionOpts pk11.SessionOptions, resolvePIN PINResolver, params LoadIntermediateParams) (*CA, error) {
	// Checked first, before the token is touched at all: it costs nothing,
	// and a service that comes up only to reject every issuance with
	// ErrNoDistributionPoints has failed in the least useful place. Startup
	// is where an operator is watching.
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
	// BasicConstraints must be present and marked valid before IsCA or
	// MaxPathLenZero mean anything: crypto/x509 leaves both at their zero
	// values when the extension is absent. IsCA=false already rejects that
	// case, so this is belt-and-braces — but it states the dependency
	// rather than leaving it to be re-derived by the next reader.
	if !cert.BasicConstraintsValid {
		return fmt.Errorf("%w: %s carries no basicConstraints extension, so it asserts no CA status at all (RFC 5280 §4.2.1.9)",
			ErrNotAnIntermediate, path)
	}
	if !cert.IsCA {
		return fmt.Errorf("%w: %s is not a CA certificate (IsCA=false)", ErrNotAnIntermediate, path)
	}
	// A self-signed certificate is one that verifies under its own public
	// key. Comparing Subject and Issuer alone would not do: those strings
	// are attacker- or operator-controlled and say nothing about who
	// actually signed the certificate.
	if err := cert.CheckSignatureFrom(cert); err == nil {
		return fmt.Errorf("%w: %s is self-signed, which means it is a root — this service holds the intermediate only, and the root must stay offline",
			ErrRootCertificateRejected, path)
	}
	if !cert.MaxPathLenZero {
		return fmt.Errorf("%w: %s does not carry pathlen:0, so it is permitted to certify further CAs; this platform's hierarchy is two tiers",
			ErrNotAnIntermediate, path)
	}
	// keyUsage decides what this certificate is *allowed* to do, and a
	// compliant verifier enforces it independently of basicConstraints
	// (RFC 5280 §4.2.1.3). An intermediate missing keyCertSign produces
	// leaves every such verifier rejects; missing cRLSign, the CRL this
	// service publishes is rejected the same way — and this service signs
	// both, so both are required rather than one being optional.
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return fmt.Errorf("%w: %s does not assert the keyCertSign key usage, so every certificate signed under it is rejected by a compliant verifier (RFC 5280 §4.2.1.3)",
			ErrNotAnIntermediate, path)
	}
	if cert.KeyUsage&x509.KeyUsageCRLSign == 0 {
		return fmt.Errorf("%w: %s does not assert the cRLSign key usage, and this service publishes the CRL covering the certificates it issues (GET /crl)",
			ErrNotAnIntermediate, path)
	}
	// An expired or not-yet-valid intermediate cannot produce a usable
	// certificate: RFC 5280 §6.1.3 validates every certificate in the path
	// against the same instant. Refusing at startup, where an operator is
	// watching, beats coming up and failing every issuance later
	//. Issue re-checks per issuance, because a service
	// that started before the expiry is still running after it.
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
		return fmt.Errorf("%w: HSM key %q is not the key certified by %s — the service would sign with a key the certificate does not attest to",
			ErrKeyCertMismatch, keyLabel, certPath)
	}
	return nil
}

// loadCertPEM reads the single PEM certificate at path.
//
// A file with a second block is rejected rather than silently reduced to
// its first. The likely way that happens is an operator pasting a whole
// chain into ca.intermediate_cert_path, and picking the first block would
// make the choice by file order — which is nobody's decision (the engineering contract
// the identity rule, and failing closed on not degrading to a weaker path).
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
