package ca

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"time"

	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

// LoadIntermediateParams configures LoadIntermediate.
//
// Note what is absent, and must stay absent: nothing here names the root's
// token, workspace, or key label. The service holds the intermediate and
// only the intermediate; the root exists solely inside the offline ceremony
// (RunCeremony) and is never reachable from a running server's configuration
// (docs/phases/phase-3b-pki-hardening.md).
type LoadIntermediateParams struct {
	// KeyLabel is the CKA_LABEL of the intermediate's key pair on the token
	// this service authenticates. The ceremony created it under a versioned
	// label (CLAUDE.md §3.7).
	KeyLabel string
	// CertPath is the ceremony-produced intermediate certificate, PEM. It
	// contains no private key material — the intermediate's private key
	// never leaves the HSM.
	CertPath string
	Curve    pk11.ECCurve
	// CertTTL is the validity window Issue gives every leaf this CA signs.
	CertTTL time.Duration
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
// never a state to repair (CLAUDE.md §3.4).
//
// Four properties of the loaded certificate are checked before the service
// is allowed to come up, each of them fail-closed:
//
//   - It must be a CA certificate. Signing leaves with a non-CA certificate
//     produces a chain no compliant verifier accepts.
//   - It must NOT be self-signed. A self-signed CA certificate here means
//     the operator has pointed the online service at a root, which is the
//     precise misconfiguration this phase exists to make impossible.
//   - It must carry pathlen:0. This platform's hierarchy is two tiers
//     (CLAUDE.md §3.6); an online CA permitted to certify further CAs has a
//     blast radius the design does not accept.
//   - Its public key must match the HSM key found under KeyLabel. Without
//     this check, a certificate and a key label that refer to different key
//     pairs would load cleanly and then produce signatures that verify
//     against nothing — a failure that would surface at the relying party
//     rather than at startup.
func LoadIntermediate(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, sessionOpts pk11.SessionOptions, resolvePIN PINResolver, params LoadIntermediateParams) (*CA, error) {
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

	return &CA{cert: cert, signer: signer, certTTL: params.CertTTL}, nil
}

// checkIntermediateCert enforces the tier constraints described on
// LoadIntermediate.
func checkIntermediateCert(cert *x509.Certificate, path string) error {
	if !cert.IsCA {
		return fmt.Errorf("%w: %s is not a CA certificate (IsCA=false)", ErrNotAnIntermediate, path)
	}
	// A self-signed certificate is one that verifies under its own public
	// key. Comparing Subject and Issuer alone would not do: those strings
	// are attacker- or operator-controlled and say nothing about who
	// actually signed the certificate.
	if err := cert.CheckSignatureFrom(cert); err == nil {
		return fmt.Errorf("%w: %s is self-signed, which means it is a root — this service holds the intermediate only, and the root must stay offline (docs/phases/phase-3b-pki-hardening.md)",
			ErrRootCertificateRejected, path)
	}
	if !cert.MaxPathLenZero {
		return fmt.Errorf("%w: %s does not carry pathlen:0, so it is permitted to certify further CAs; this platform's hierarchy is two tiers (CLAUDE.md §3.6)",
			ErrNotAnIntermediate, path)
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

func loadCertPEM(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("ca: reading CA certificate %s: %w", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("ca: %s does not contain a PEM block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing CA certificate %s: %w", path, err)
	}
	return cert, nil
}
