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
	"strings"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// newTestCA returns the issuing CA these tests exercise: a ceremony-produced
// intermediate over two freshly provisioned tokens. The service refuses to
// run on a root, so the tests do not run against one either.
func newTestCA(t *testing.T, b *ceremonyBackend) *ca.CA {
	t.Helper()
	c, _ := newTestCAWithRoot(t, b)
	return c
}

// newTestCAWithRoot is newTestCA plus the ceremony's root certificate as
// DER, used only as a trust anchor. Nothing here signs with the root.
func newTestCAWithRoot(t *testing.T, b *ceremonyBackend) (*ca.CA, []byte) {
	t.Helper()
	ctx := context.Background()

	result, err := ca.RunCeremony(ctx, b.adapter, pk11.SessionOptions{}, testCeremonyParams(b))
	if err != nil {
		t.Fatalf("RunCeremony: %v", err)
	}
	interCert, err := x509.ParseCertificate(result.IntermediateCertDER)
	if err != nil {
		t.Fatalf("parsing intermediate certificate: %v", err)
	}

	if err := b.adapter.LoginToken(ctx, b.interWS, []byte(b.interPIN), pk11.RoleUser); err != nil {
		t.Fatalf("LoginToken (intermediate): %v", err)
	}
	t.Cleanup(func() { _ = b.adapter.LogoutToken(ctx) })

	signer, err := ca.NewSigner(ctx, b.adapter, b.interWS, pk11.SessionOptions{}, b.interKeyLabel(), pk11.P256)
	if err != nil {
		t.Fatalf("NewSigner (intermediate): %v", err)
	}
	return ca.NewCA(interCert, signer, time.Hour, testLeafDistribution()), result.RootCertDER
}

// signedCSR builds and signs a CSR with priv, then parses it back, so the
// test exercises the bytes Issue receives over the wire.
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
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c := newTestCA(t, b)
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
	})
}

// TestIssue_OpenSSLVerify: an issued certificate passes openssl verify
// against the real chain. The trust anchor is the offline root and the
// intermediate is supplied as an untrusted path-building certificate,
// which is what a relying party does.
func TestIssue_OpenSSLVerify(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		if _, err := exec.LookPath("openssl"); err != nil {
			t.Skip("openssl not found on PATH")
		}
		c, rootDER := newTestCAWithRoot(t, b)
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
		caPath := filepath.Join(dir, "root.pem")
		interPath := filepath.Join(dir, "intermediate.pem")
		leafPath := filepath.Join(dir, "leaf.pem")
		if err := os.WriteFile(caPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER}), 0644); err != nil {
			t.Fatalf("WriteFile(root): %v", err)
		}
		if err := os.WriteFile(interPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate().Raw}), 0644); err != nil {
			t.Fatalf("WriteFile(intermediate): %v", err)
		}
		if err := os.WriteFile(leafPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw}), 0644); err != nil {
			t.Fatalf("WriteFile(leaf): %v", err)
		}

		out, err := exec.Command("openssl", "verify", "-CAfile", caPath, "-untrusted", interPath, leafPath).CombinedOutput()
		if err != nil {
			t.Fatalf("openssl verify: %v: %s", err, out)
		}
	})
}

func TestIssue_SerialsAreUnique(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c := newTestCA(t, b)
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
	})
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
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c := newTestCA(t, b)
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		// x509.CreateCertificateRequest verifies its own output, so the CSR
		// is built honestly and a bit is flipped inside the signature BIT
		// STRING afterwards.
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
	})
}

func TestIssue_EmptySubjectRejected(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c := newTestCA(t, b)
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		csr := signedCSR(t, priv, pkix.Name{})

		if _, err := c.Issue(csr); !errors.Is(err, ca.ErrEmptySubject) {
			t.Fatalf("Issue with an empty subject = %v, want ErrEmptySubject", err)
		}
	})
}

func TestIssue_DisallowedCurveRejected(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c := newTestCA(t, b)
		priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		csr := signedCSR(t, priv, pkix.Name{CommonName: "p224.example.test"})

		if _, err := c.Issue(csr); !errors.Is(err, ca.ErrDisallowedKeyType) {
			t.Fatalf("Issue with a P-224 key = %v, want ErrDisallowedKeyType", err)
		}
	})
}

func TestIssue_ShortRSAKeyRejected(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c := newTestCA(t, b)
		priv, err := rsa.GenerateKey(rand.Reader, 1024)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		csr := signedCSR(t, priv, pkix.Name{CommonName: "short-rsa.example.test"})

		if _, err := c.Issue(csr); !errors.Is(err, ca.ErrDisallowedKeyType) {
			t.Fatalf("Issue with a 1024-bit RSA key = %v, want ErrDisallowedKeyType", err)
		}
	})
}

func TestIssue_UnsupportedKeyAlgorithmRejected(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c := newTestCA(t, b)
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		csr := signedCSR(t, priv, pkix.Name{CommonName: "ed25519.example.test"})

		if _, err := c.Issue(csr); !errors.Is(err, ca.ErrDisallowedKeyType) {
			t.Fatalf("Issue with an Ed25519 key = %v, want ErrDisallowedKeyType", err)
		}
	})
}

// TestIssue_KeyUsageMatchesKeyAlgorithm: the template once asserted
// keyEncipherment unconditionally, an RSA operation an EC key cannot
// perform (RFC 5480 §3), on every P-256 certificate this CA issued.
func TestIssue_KeyUsageMatchesKeyAlgorithm(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c := newTestCA(t, b)

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
	})
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
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c := newTestCA(t, b)
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
	})
}

// TestIssue_SetsDistributionPoints: every leaf says where its revocation
// status is published and where the issuing certificate can be fetched.
// No OCSP URL is written, because no responder exists.
func TestIssue_SetsDistributionPoints(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c := newTestCA(t, b)
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		csr := signedCSR(t, priv, pkix.Name{CommonName: "dist-points.example.test"})

		cert, err := c.Issue(csr)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}

		if got := cert.CRLDistributionPoints; len(got) != 1 || got[0] != testLeafCRLURL {
			t.Fatalf("CRLDistributionPoints = %v, want [%s]", got, testLeafCRLURL)
		}
		if got := cert.IssuingCertificateURL; len(got) != 1 || got[0] != testLeafIssuerURL {
			t.Fatalf("IssuingCertificateURL = %v, want [%s]", got, testLeafIssuerURL)
		}
		if len(cert.OCSPServer) != 0 {
			t.Fatalf("leaf names an OCSP responder %v, but no responder exists", cert.OCSPServer)
		}
		// The leaf's CDP must be the intermediate's CRL, never the root's,
		// which never lists a leaf.
		if cert.CRLDistributionPoints[0] == testRootCRLURL {
			t.Fatal("leaf CDP points at the root CRL, which covers the intermediate and never lists leaves")
		}
	})
}

// TestIssue_FailsClosedWithoutDistributionPoints: a leaf issued without a
// CRL distribution point can never gain one, so Issue refuses. No token is
// needed; the check runs before anything is signed.
func TestIssue_FailsClosedWithoutDistributionPoints(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	csr := signedCSR(t, priv, pkix.Name{CommonName: "no-dist.example.test"})

	for _, tc := range []struct {
		name string
		dist ca.LeafDistribution
	}{
		{"both unset", ca.LeafDistribution{}},
		{"no CRL URL", ca.LeafDistribution{IssuerCertURL: testLeafIssuerURL}},
		{"no issuer URL", ca.LeafDistribution{CRLURL: testLeafCRLURL}},
		{"unfetchable CRL scheme", ca.LeafDistribution{CRLURL: "ldap://pki.example.test/crl", IssuerCertURL: testLeafIssuerURL}},
		{"CRL URL without a host", ca.LeafDistribution{CRLURL: "http:///crl", IssuerCertURL: testLeafIssuerURL}},
		{"unfetchable issuer scheme", ca.LeafDistribution{CRLURL: testLeafCRLURL, IssuerCertURL: "file:///etc/intermediate.crt"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A nil signer: if the guard ever stopped running first, this
			// would panic rather than pass.
			c := ca.NewCA(&x509.Certificate{}, nil, time.Hour, tc.dist)
			if _, err := c.Issue(csr); !errors.Is(err, ca.ErrNoDistributionPoints) {
				t.Fatalf("Issue error = %v, want ErrNoDistributionPoints", err)
			}
		})
	}
}

// TestIssue_OpenSSLShowsDistributionPoints asserts that openssl reads the
// same CDP and AIA out of the DER that crypto/x509 does.
func TestIssue_OpenSSLShowsDistributionPoints(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		if _, err := exec.LookPath("openssl"); err != nil {
			t.Skip("openssl not found on PATH")
		}
		c := newTestCA(t, b)
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}
		csr := signedCSR(t, priv, pkix.Name{CommonName: "openssl-dist.example.test"})
		cert, err := c.Issue(csr)
		if err != nil {
			t.Fatalf("Issue: %v", err)
		}

		leafPath := filepath.Join(t.TempDir(), "leaf.pem")
		writePEM(t, leafPath, "CERTIFICATE", cert.Raw)
		out, err := exec.Command("openssl", "x509", "-in", leafPath, "-text", "-noout").CombinedOutput()
		if err != nil {
			t.Fatalf("openssl x509 -text: %v: %s", err, out)
		}
		text := string(out)

		for _, want := range []string{
			"X509v3 CRL Distribution Points",
			"URI:" + testLeafCRLURL,
			"Authority Information Access",
			"CA Issuers - URI:" + testLeafIssuerURL,
		} {
			if !strings.Contains(text, want) {
				t.Fatalf("openssl x509 -text output does not contain %q:\n%s", want, text)
			}
		}
		if strings.Contains(text, "OCSP - URI") {
			t.Fatalf("openssl x509 -text output names an OCSP responder, and no responder exists:\n%s", text)
		}
	})
}
