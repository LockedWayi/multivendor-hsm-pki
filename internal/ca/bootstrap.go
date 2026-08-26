package ca

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

// DefaultRootValidity is how long a freshly bootstrapped CA certificate is
// valid for. Deliberately much longer than an issued leaf certificate's TTL
// (config.example.yaml's ca.cert_ttl_hours, which governs Issue, not
// Bootstrap): a root that outlives many leaf-certificate rotations is the
// normal shape of a CA hierarchy, even one this small.
const DefaultRootValidity = 10 * 365 * 24 * time.Hour

// BootstrapParams configures Bootstrap. KeyLabel and CertPath together
// answer the question Bootstrap exists to answer — "does a CA already
// exist, or do we need to create one" — so both are required.
type BootstrapParams struct {
	// KeyLabel is the CKA_LABEL the CA's key pair is created with, and is
	// looked up by on every later restart.
	KeyLabel string
	// CertPath is where the CA's self-signed certificate (PEM, not
	// secret — it contains no private key material) is read from and
	// written to. The private key never leaves the HSM; only the public
	// certificate touches disk.
	CertPath string
	Curve    pk11.ECCurve
	Subject  pkix.Name
	// RootValidity defaults to DefaultRootValidity when zero.
	RootValidity time.Duration
	// CertTTL is the validity window Issue gives every certificate this CA
	// signs afterward.
	CertTTL time.Duration
}

// Bootstrap loads an existing CA or creates one, deciding which by checking
// two independent signals: whether a key pair with KeyLabel already exists
// on the HSM, and whether a certificate file already exists at CertPath.
//
//   - Both present: load the existing CA (the normal path on every restart
//     after the first).
//   - Neither present: generate a new key pair in the HSM and self-sign a
//     new CA certificate — the very first startup.
//   - Only one present: refuse to guess. A key without a matching
//     certificate, or a certificate file without its key, is not a state
//     this function will silently repair — doing so could mean signing a
//     new certificate that does not match the operator's actual HSM key,
//     or generating a second key under a label that was supposed to be
//     unique (CLAUDE.md §3.4, fail closed).
func Bootstrap(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, sessionOpts pk11.SessionOptions, resolvePIN PINResolver, params BootstrapParams) (*CA, error) {
	if params.RootValidity == 0 {
		params.RootValidity = DefaultRootValidity
	}

	// Authenticate the token once, here, for the service's lifetime.
	// Everything below — and every later signing call — runs on sessions
	// that inherit this, with no login of their own. See
	// internal/pkcs11/tokenlogin.go for why per-operation login cannot be
	// made concurrency-safe.
	if !adapter.TokenLoggedIn() {
		pin, err := resolvePIN()
		if err != nil {
			return nil, fmt.Errorf("ca: resolving PIN: %w", err)
		}
		if err := adapter.LoginToken(ctx, ws, pin, pk11.RoleUser); err != nil {
			return nil, fmt.Errorf("ca: token login: %w", err)
		}
	}

	keyExists, err := keyPairExists(ctx, adapter, ws, sessionOpts, params.KeyLabel)
	if err != nil {
		return nil, err
	}
	certExists, err := certFileExists(params.CertPath)
	if err != nil {
		return nil, err
	}

	switch {
	case keyExists && certExists:
		return loadExisting(ctx, adapter, ws, sessionOpts, params)
	case !keyExists && !certExists:
		return bootstrapNew(ctx, adapter, ws, sessionOpts, params)
	default:
		return nil, fmt.Errorf(
			"ca: inconsistent bootstrap state for key label %q: HSM key exists=%v, cert file %q exists=%v — refusing to guess which one is stale",
			params.KeyLabel, keyExists, params.CertPath, certExists)
	}
}

func loadExisting(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, sessionOpts pk11.SessionOptions, params BootstrapParams) (*CA, error) {
	cert, err := loadCertPEM(params.CertPath)
	if err != nil {
		return nil, err
	}
	signer, err := NewSigner(ctx, adapter, ws, sessionOpts, params.KeyLabel, params.Curve)
	if err != nil {
		return nil, err
	}
	return &CA{cert: cert, signer: signer, certTTL: params.CertTTL}, nil
}

func bootstrapNew(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, sessionOpts pk11.SessionOptions, params BootstrapParams) (*CA, error) {
	_, err := withSession(ctx, adapter, ws, sessionOpts, func(s *pk11.Session) (struct{}, error) {
		_, err := adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
			Curve: params.Curve, Label: params.KeyLabel, Sign: true, Verify: true,
		})
		return struct{}{}, err
	})
	if err != nil {
		return nil, fmt.Errorf("ca: generating CA key pair: %w", err)
	}

	signer, err := NewSigner(ctx, adapter, ws, sessionOpts, params.KeyLabel, params.Curve)
	if err != nil {
		return nil, err
	}

	ski, err := subjectKeyID(signer.Public())
	if err != nil {
		return nil, err
	}
	serial, err := GenerateSerial()
	if err != nil {
		return nil, err
	}

	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               params.Subject,
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.Add(params.RootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
	if err != nil {
		return nil, fmt.Errorf("ca: self-signing CA certificate: %w", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("ca: parsing freshly-signed CA certificate: %w", err)
	}
	if err := writeCertPEM(params.CertPath, der); err != nil {
		return nil, err
	}

	return &CA{cert: cert, signer: signer, certTTL: params.CertTTL}, nil
}

// keyPairExists reports whether a private key with label already exists on
// the token, distinguishing "does not exist" (ErrKeyNotFound) from any
// other error opening a session or searching for it.
func keyPairExists(ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, sessionOpts pk11.SessionOptions, label string) (bool, error) {
	return withSession(ctx, adapter, ws, sessionOpts, func(s *pk11.Session) (bool, error) {
		_, err := findKeyByLabel(ctx, adapter, s, pk11.ClassPrivateKey, label)
		if errors.Is(err, ErrKeyNotFound) {
			return false, nil
		}
		if err != nil {
			return false, err
		}
		return true, nil
	})
}

func certFileExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, fmt.Errorf("ca: checking cert path %s: %w", path, err)
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

// writeCertPEM writes der as a PEM-encoded certificate file. The CA
// certificate contains no private key material, so 0644 (world-readable)
// is appropriate — unlike a PIN or private key, this is meant to be handed
// to anyone who needs to verify certificates this CA issues.
func writeCertPEM(path string, der []byte) error {
	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0644); err != nil {
		return fmt.Errorf("ca: writing CA certificate %s: %w", path, err)
	}
	return nil
}
