package ca

// White-box tests for the intermediate-certificate checks. They build
// certificates in software: every property here is a property of the
// certificate, not of the key. The token-backed path is in
// intermediate_test.go.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// intermediateOpts describes a certificate to build. The zero value is a
// valid intermediate; each test changes one thing.
type intermediateOpts struct {
	notCA                 bool
	noBasicConstraints    bool
	noPathLenZero         bool
	keyUsage              x509.KeyUsage
	notBefore             time.Time
	notAfter              time.Time
	selfSigned            bool
	omitKeyUsageDefaulted bool
}

func buildIntermediate(t *testing.T, o intermediateOpts) *x509.Certificate {
	t.Helper()
	cert, _ := buildIntermediateWithKey(t, o)
	return cert
}

// buildIntermediateWithKey also returns the intermediate's private key, for
// the tests that need to sign under it.
func buildIntermediateWithKey(t *testing.T, o intermediateOpts) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey(intermediate): %v", err)
	}
	now := time.Now()

	rootTpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test root"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		SubjectKeyId:          []byte{1, 2, 3, 4},
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTpl, rootTpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatalf("CreateCertificate(root): %v", err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatalf("ParseCertificate(root): %v", err)
	}

	keyUsage := o.keyUsage
	if !o.omitKeyUsageDefaulted && keyUsage == 0 {
		keyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	}
	notBefore, notAfter := o.notBefore, o.notAfter
	if notBefore.IsZero() {
		notBefore = now.Add(-time.Hour)
	}
	if notAfter.IsZero() {
		notAfter = now.Add(24 * time.Hour)
	}

	tpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test intermediate"},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              keyUsage,
		BasicConstraintsValid: !o.noBasicConstraints,
		IsCA:                  !o.notCA,
		MaxPathLen:            0,
		MaxPathLenZero:        !o.noPathLenZero,
		SubjectKeyId:          []byte{5, 6, 7, 8},
	}
	if o.noPathLenZero {
		tpl.MaxPathLen, tpl.MaxPathLenZero = 1, false
	}
	if o.notCA {
		// crypto/x509 refuses a path length on a non-CA template.
		tpl.MaxPathLen, tpl.MaxPathLenZero = 0, false
	}

	parent, signer := root, rootKey
	if o.selfSigned {
		parent, signer = tpl, interKey
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, parent, &interKey.PublicKey, signer)
	if err != nil {
		t.Fatalf("CreateCertificate(intermediate): %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("ParseCertificate(intermediate): %v", err)
	}
	return cert, interKey
}

func TestCheckIntermediateCert_AcceptsAWellFormedIntermediate(t *testing.T) {
	if err := checkIntermediateCert(buildIntermediate(t, intermediateOpts{}), "test.pem"); err != nil {
		t.Fatalf("checkIntermediateCert rejected a valid intermediate: %v", err)
	}
}

// TestCheckIntermediateCert_RejectsMissingKeyUsages: a compliant verifier
// enforces keyUsage independently of basicConstraints (RFC 5280
// §4.2.1.3), so an intermediate without keyCertSign issues certificates
// the rest of the world rejects.
func TestCheckIntermediateCert_RejectsMissingKeyUsages(t *testing.T) {
	for _, tc := range []struct {
		name  string
		usage x509.KeyUsage
		want  string
	}{
		{"no keyCertSign", x509.KeyUsageCRLSign, "keyCertSign"},
		{"no cRLSign", x509.KeyUsageCertSign, "cRLSign"},
		{"neither", x509.KeyUsageDigitalSignature, "keyCertSign"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := buildIntermediate(t, intermediateOpts{keyUsage: tc.usage})
			err := checkIntermediateCert(cert, "test.pem")
			if !errors.Is(err, ErrNotAnIntermediate) {
				t.Fatalf("error = %v, want ErrNotAnIntermediate", err)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not name the missing usage %q", err, tc.want)
			}
		})
	}
}

// TestCheckIntermediateCert_RejectsOutsideValidityWindow covers both ends.
// RFC 5280 §6.1.3 validates every certificate in a path at one instant.
func TestCheckIntermediateCert_RejectsOutsideValidityWindow(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name                string
		notBefore, notAfter time.Time
	}{
		{"expired", now.Add(-48 * time.Hour), now.Add(-time.Hour)},
		{"not yet valid", now.Add(time.Hour), now.Add(48 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert := buildIntermediate(t, intermediateOpts{notBefore: tc.notBefore, notAfter: tc.notAfter})
			if err := checkIntermediateCert(cert, "test.pem"); !errors.Is(err, ErrIssuerNotValid) {
				t.Fatalf("error = %v, want ErrIssuerNotValid", err)
			}
		})
	}
}

func TestCheckIntermediateCert_RejectsStructuralFaults(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts intermediateOpts
		want error
	}{
		{"not a CA", intermediateOpts{notCA: true}, ErrNotAnIntermediate},
		{"no basicConstraints", intermediateOpts{noBasicConstraints: true}, ErrNotAnIntermediate},
		{"not pathlen:0", intermediateOpts{noPathLenZero: true}, ErrNotAnIntermediate},
		{"self-signed root", intermediateOpts{selfSigned: true}, ErrRootCertificateRejected},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkIntermediateCert(buildIntermediate(t, tc.opts), "test.pem"); !errors.Is(err, tc.want) {
				t.Fatalf("error = %v, want %v", err, tc.want)
			}
		})
	}
}

// TestLoadCertPEM_RejectsMoreThanOneBlock: a chain pasted into
// ca.intermediate_cert_path is refused rather than reduced to its first
// certificate.
func TestLoadCertPEM_RejectsMoreThanOneBlock(t *testing.T) {
	cert := buildIntermediate(t, intermediateOpts{})
	single := pemBlock(t, cert.Raw)

	dir := t.TempDir()
	onePath := filepath.Join(dir, "one.pem")
	if err := os.WriteFile(onePath, single, 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	if _, err := loadCertPEM(onePath); err != nil {
		t.Fatalf("loadCertPEM rejected a single-certificate file: %v", err)
	}

	chainPath := filepath.Join(dir, "chain.pem")
	if err := os.WriteFile(chainPath, append(append([]byte{}, single...), single...), 0600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	_, err := loadCertPEM(chainPath)
	if err == nil {
		t.Fatal("loadCertPEM accepted a file with two PEM blocks, want an error")
	}
	if !strings.Contains(err.Error(), "more than one PEM block") {
		t.Fatalf("error %q does not explain the real problem", err)
	}
}

// TestKeyUsageFor_CoversEveryAllowedKeyType pins keyUsageFor's switch to
// validateCSR's allow-list, so a key type added to one and not the other
// does not get a keyUsage decided by a default branch.
func TestKeyUsageFor_CoversEveryAllowedKeyType(t *testing.T) {
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	if got := keyUsageFor(&ecKey.PublicKey); got != x509.KeyUsageDigitalSignature {
		t.Fatalf("ECDSA keyUsage = %v, want digitalSignature only: an EC key cannot do keyEncipherment (RFC 5480 §3)", got)
	}
	// RSA is exercised through Issue in ca_test.go, where a 2048-bit key is
	// already generated.
}

func pemBlock(t *testing.T, der []byte) []byte {
	t.Helper()
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// testDist is a valid leaf distribution pair for the Issue tests below.
func testDist() LeafDistribution {
	return LeafDistribution{
		CRLURL:        "https://pki.example.test/crl",
		IssuerCertURL: "https://pki.example.test/intermediate.crt",
	}
}

func testCSR(t *testing.T) *x509.CertificateRequest {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: "leaf.example.test"}}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		t.Fatalf("ParseCertificateRequest: %v", err)
	}
	return csr
}

// TestIssue_RefusesAnIssuerOutsideItsOwnValidityWindow: startup validated
// the intermediate, and then it expired while the process kept serving.
func TestIssue_RefusesAnIssuerOutsideItsOwnValidityWindow(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct {
		name                string
		notBefore, notAfter time.Time
	}{
		{"expired issuer", now.Add(-48 * time.Hour), now.Add(-time.Minute)},
		{"issuer not yet valid", now.Add(time.Hour), now.Add(48 * time.Hour)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cert, key := buildIntermediateWithKey(t, intermediateOpts{notBefore: tc.notBefore, notAfter: tc.notAfter})
			c := NewCA(cert, key, time.Minute, testDist())
			if _, err := c.Issue(testCSR(t)); !errors.Is(err, ErrIssuerNotValid) {
				t.Fatalf("Issue error = %v, want ErrIssuerNotValid", err)
			}
		})
	}
}

// TestIssue_RefusesALeafThatWouldOutliveItsIssuer pins refuse over clamp.
func TestIssue_RefusesALeafThatWouldOutliveItsIssuer(t *testing.T) {
	now := time.Now()
	cert, key := buildIntermediateWithKey(t, intermediateOpts{
		notBefore: now.Add(-time.Hour),
		notAfter:  now.Add(time.Hour),
	})
	// Issuer has an hour left; the configured leaf TTL is a day.
	c := NewCA(cert, key, 24*time.Hour, testDist())

	_, err := c.Issue(testCSR(t))
	if !errors.Is(err, ErrValidityExceedsIssuer) {
		t.Fatalf("Issue error = %v, want ErrValidityExceedsIssuer", err)
	}

	// A TTL inside the window still issues.
	c = NewCA(cert, key, time.Minute, testDist())
	leaf, err := c.Issue(testCSR(t))
	if err != nil {
		t.Fatalf("Issue with a TTL inside the issuer's window: %v", err)
	}
	if leaf.NotAfter.After(cert.NotAfter) {
		t.Fatalf("issued leaf NotAfter %s is after the issuer's %s", leaf.NotAfter, cert.NotAfter)
	}
}
