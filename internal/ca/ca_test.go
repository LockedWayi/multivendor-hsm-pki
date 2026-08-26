package ca_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/ca"
	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

// newTestCA bootstraps a fresh CA over a freshly provisioned SoftHSM2 token.
func newTestCA(t *testing.T) *ca.CA {
	t.Helper()
	adapter, ws, resolvePIN := newTestAdapter(t)

	c, err := ca.Bootstrap(context.Background(), adapter, ws, pk11.SessionOptions{}, resolvePIN, ca.BootstrapParams{
		KeyLabel:     "ca-issue-test-key",
		CertPath:     filepath.Join(t.TempDir(), "ca-cert.pem"),
		Curve:        pk11.P256,
		Subject:      pkix.Name{CommonName: "hsm-pki-platform test CA"},
		RootValidity: 24 * time.Hour,
		CertTTL:      time.Hour,
	})
	if err != nil {
		t.Fatalf("Bootstrap: %v", err)
	}
	return c
}

// signedCSR builds and signs a CSR with priv (an *ecdsa.PrivateKey,
// *rsa.PrivateKey, or ed25519.PrivateKey), then parses it back — exercising
// the exact bytes Issue would receive over the wire.
func signedCSR(t *testing.T, priv crypto.Signer, subject pkix.Name) *x509.CertificateRequest {
	t.Helper()
	template := &x509.CertificateRequest{Subject: subject}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	return csr
}

func TestIssue_Success(t *testing.T) {
	c := newTestCA(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csr := signedCSR(t, priv, pkix.Name{CommonName: "leaf.example.test"})

	cert, err := c.Issue(csr)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	if err := cert.CheckSignatureFrom(c.Certificate()); err != nil {
		t.Fatalf("CheckSignatureFrom(ca): %v", err)
	}
}

// TestIssue_OpenSSLVerify is sub-task 2.3's own Done-when criterion: an
// issued certificate passes `openssl verify` against the CA certificate.
func TestIssue_OpenSSLVerify(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not found on PATH")
	}
	c := newTestCA(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csr := signedCSR(t, priv, pkix.Name{CommonName: "openssl-check.example.test"})

	cert, err := c.Issue(csr)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	dir := t.TempDir()
	caPath := filepath.Join(dir, "ca.pem")
	leafPath := filepath.Join(dir, "leaf.pem")
	if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate().Raw}), 0644); err != nil {
		t.Fatalf("WriteFile(ca): %v", err)
	}
	if err := os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0644); err != nil {
		t.Fatalf("WriteFile(leaf): %v", err)
	}

	out, err := exec.Command("openssl", "verify", "-CAfile", caPath, leafPath).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl verify: %v: %s", err, out)
	}
}

func TestIssue_SerialsAreUnique(t *testing.T) {
	c := newTestCA(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csr := signedCSR(t, priv, pkix.Name{CommonName: "serial-test.example.test"})

	first, err := c.Issue(csr)
	if err != nil {
		t.Fatalf("Issue (1st): %v", err)
	}
	second, err := c.Issue(csr)
	if err != nil {
		t.Fatalf("Issue (2nd): %v", err)
	}
	if first.SerialNumber.Cmp(second.SerialNumber) == 0 {
		t.Fatalf("two Issue calls returned the same serial number: %v", first.SerialNumber)
	}
}

func TestGenerateSerial_AtLeast64Bits(t *testing.T) {
	serial, err := ca.GenerateSerial()
	if err != nil {
		t.Fatalf("GenerateSerial: %v", err)
	}
	if serial.BitLen() < 64 {
		t.Fatalf("GenerateSerial returned a %d-bit value, want >= 64", serial.BitLen())
	}
	if serial.Sign() <= 0 {
		t.Fatalf("GenerateSerial returned a non-positive value: %v", serial)
	}
}

func TestIssue_InvalidSignatureRejected(t *testing.T) {
	c := newTestCA(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	// x509.CreateCertificateRequest verifies its own output before
	// returning, so a CSR with a genuinely mismatched signature cannot be
	// built through it — construct one honestly, then flip a bit inside the
	// trailing signature BIT STRING to invalidate it without touching the
	// surrounding DER's length-prefixed structure.
	template := &x509.CertificateRequest{Subject: pkix.Name{CommonName: "bad-signature.example.test"}}
	der, err := x509.CreateCertificateRequest(rand.Reader, template, priv)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	tampered := append([]byte(nil), der...)
	tampered[len(tampered)-1] ^= 0xFF
	csr, err := x509.ParseCertificateRequest(tampered)
	if err != nil {
		t.Fatalf("ParseCertificateRequest(tampered): %v", err)
	}

	if _, err := c.Issue(csr); !errors.Is(err, ca.ErrInvalidCSRSignature) {
		t.Fatalf("Issue with a tampered CSR signature = %v, want ErrInvalidCSRSignature", err)
	}
}

func TestIssue_EmptySubjectRejected(t *testing.T) {
	c := newTestCA(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csr := signedCSR(t, priv, pkix.Name{})

	if _, err := c.Issue(csr); !errors.Is(err, ca.ErrEmptySubject) {
		t.Fatalf("Issue with an empty subject = %v, want ErrEmptySubject", err)
	}
}

func TestIssue_DisallowedCurveRejected(t *testing.T) {
	c := newTestCA(t)
	priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csr := signedCSR(t, priv, pkix.Name{CommonName: "p224.example.test"})

	if _, err := c.Issue(csr); !errors.Is(err, ca.ErrDisallowedKeyType) {
		t.Fatalf("Issue with a P-224 key = %v, want ErrDisallowedKeyType", err)
	}
}

func TestIssue_ShortRSAKeyRejected(t *testing.T) {
	c := newTestCA(t)
	priv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csr := signedCSR(t, priv, pkix.Name{CommonName: "short-rsa.example.test"})

	if _, err := c.Issue(csr); !errors.Is(err, ca.ErrDisallowedKeyType) {
		t.Fatalf("Issue with a 1024-bit RSA key = %v, want ErrDisallowedKeyType", err)
	}
}

func TestIssue_UnsupportedKeyAlgorithmRejected(t *testing.T) {
	c := newTestCA(t)
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csr := signedCSR(t, priv, pkix.Name{CommonName: "ed25519.example.test"})

	if _, err := c.Issue(csr); !errors.Is(err, ca.ErrDisallowedKeyType) {
		t.Fatalf("Issue with an Ed25519 key = %v, want ErrDisallowedKeyType", err)
	}
}

// TestIssue_KeyUsageMatchesKeyAlgorithm guards a standards bug: the
// template asserted keyEncipherment unconditionally, which describes an
// RSA operation an EC key cannot perform (RFC 5480 §3) — and P-256 is this
// CA's default curve, so every certificate it issued carried it wrongly.
func TestIssue_KeyUsageMatchesKeyAlgorithm(t *testing.T) {
	c := newTestCA(t)

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ecCert, err := c.Issue(signedCSR(t, ecKey, pkix.Name{CommonName: "ec.example.test"}))
	if err != nil {
		t.Fatalf("Issue (EC): %v", err)
	}
	if ecCert.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		t.Error("ECDSA certificate asserts keyEncipherment, which an EC key cannot do")
	}
	if ecCert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("ECDSA certificate is missing digitalSignature")
	}

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	rsaCert, err := c.Issue(signedCSR(t, rsaKey, pkix.Name{CommonName: "rsa.example.test"}))
	if err != nil {
		t.Fatalf("Issue (RSA): %v", err)
	}
	if rsaCert.KeyUsage&x509.KeyUsageKeyEncipherment == 0 {
		t.Error("RSA certificate is missing keyEncipherment")
	}
}

func TestGenerateSerial_AlwaysPositive(t *testing.T) {
	for i := 0; i < 200; i++ {
		serial, err := ca.GenerateSerial()
		if err != nil {
			t.Fatalf("GenerateSerial: %v", err)
		}
		if serial.Sign() <= 0 {
			t.Fatalf("GenerateSerial returned a non-positive value: %v", serial)
		}
	}
}

func TestBuildCRL_RejectsInvertedValidityWindow(t *testing.T) {
	c := newTestCA(t)
	now := time.Now()

	if _, err := c.BuildCRL(nil, now, now.Add(-time.Hour), big.NewInt(1)); err == nil {
		t.Error("BuildCRL with nextUpdate before thisUpdate succeeded, want an error")
	}
	if _, err := c.BuildCRL(nil, now, now, big.NewInt(1)); err == nil {
		t.Error("BuildCRL with nextUpdate == thisUpdate succeeded, want an error")
	}
	if _, err := c.BuildCRL(nil, now, now.Add(time.Hour), big.NewInt(0)); err == nil {
		t.Error("BuildCRL with a zero CRL number succeeded, want an error")
	}
	if _, err := c.BuildCRL(nil, now, now.Add(time.Hour), nil); err == nil {
		t.Error("BuildCRL with a nil CRL number succeeded, want an error")
	}
}
