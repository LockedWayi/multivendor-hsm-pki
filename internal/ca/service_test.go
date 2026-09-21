package ca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// provisionTLSKey generates a TLS key pair on the intermediate's token and
// returns its label and signer. The token is logged in by newTestCA.
func provisionTLSKey(t *testing.T, b *ceremonyBackend) (string, *ca.Signer) {
	t.Helper()
	ctx := context.Background()
	label := b.label("tls-key-v1")
	session, err := b.adapter.OpenSession(ctx, b.interWS, pk11.SessionOptions{})
	if err != nil {
		t.Fatalf("OpenSession: %v", err)
	}
	defer b.adapter.CloseSession(ctx, session)
	if _, err := b.adapter.GenerateKeyPair(ctx, session, pk11.KeyPairRequest{
		Curve: pk11.P256, Label: label, Sign: true, Verify: true,
	}); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	signer, err := ca.NewSigner(ctx, b.adapter, b.interWS, pk11.SessionOptions{}, label, pk11.P256)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return label, signer
}

// writeLeaf issues a serverAuth leaf over key through c and writes it to a
// temporary PEM file.
func writeLeaf(t *testing.T, c *ca.CA, key any) (string, *x509.Certificate) {
	t.Helper()
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject:     pkix.Name{CommonName: "pki.example.test"},
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)},
	}, key)
	if err != nil {
		t.Fatalf("CreateCertificateRequest: %v", err)
	}
	csr, _ := x509.ParseCertificateRequest(csrDER)
	leaf, err := c.Issue(csr)
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}
	return writeCertPEMFile(t, "tls.pem", leaf.Raw), leaf
}

func writeCertPEMFile(t *testing.T, name string, der []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	return path
}

func TestLoadServiceCertificate_LoadsALeafOverTheTokenKey(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c := newTestCA(t, b)
		label, signer := provisionTLSKey(t, b)
		certPath, leaf := writeLeaf(t, c, signer)

		identity, err := ca.LoadServiceCertificate(context.Background(), b.adapter, b.interWS, pk11.SessionOptions{}, c.Certificate(), ca.ServiceCertificateParams{
			KeyLabel: label, CertPath: certPath, Curve: pk11.P256,
		})
		if err != nil {
			t.Fatalf("LoadServiceCertificate: %v", err)
		}
		if len(identity.Certificate) != 2 {
			t.Fatalf("the identity carries %d certificates, want leaf and issuer", len(identity.Certificate))
		}
		if !identity.Leaf.Equal(leaf) {
			t.Fatal("the loaded leaf is not the one written")
		}
		issuer, _ := x509.ParseCertificate(identity.Certificate[1])
		if !issuer.Equal(c.Certificate()) {
			t.Fatal("the second certificate is not the issuing intermediate")
		}
		// The key is the token's, reached through the signer, not a
		// software key.
		if _, ok := identity.PrivateKey.(*ca.Signer); !ok {
			t.Fatalf("PrivateKey is a %T, want *ca.Signer", identity.PrivateKey)
		}
	})
}

func TestLoadServiceCertificate_Refusals(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		c, rootDER := newTestCAWithRoot(t, b)
		label, signer := provisionTLSKey(t, b)
		certPath, _ := writeLeaf(t, c, signer)
		ctx := context.Background()
		load := func(keyLabel, path string, issuer *x509.Certificate) error {
			_, err := ca.LoadServiceCertificate(ctx, b.adapter, b.interWS, pk11.SessionOptions{}, issuer, ca.ServiceCertificateParams{
				KeyLabel: keyLabel, CertPath: path, Curve: pk11.P256,
			})
			return err
		}

		t.Run("the intermediate's own certificate is refused: a CA is not a TLS identity", func(t *testing.T) {
			err := load(b.interKeyLabel(), writeCertPEMFile(t, "inter.pem", c.Certificate().Raw), c.Certificate())
			if !errors.Is(err, ca.ErrNotAServiceCertificate) {
				t.Fatalf("err = %v, want ErrNotAServiceCertificate", err)
			}
		})

		t.Run("a leaf whose key is not the one under the label is refused", func(t *testing.T) {
			// A leaf over a software key, loaded against the token's label.
			soft, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			otherPath, _ := writeLeaf(t, c, soft)
			err := load(label, otherPath, c.Certificate())
			if !errors.Is(err, ca.ErrKeyCertMismatch) {
				t.Fatalf("err = %v, want ErrKeyCertMismatch", err)
			}
		})

		t.Run("a leaf the loaded intermediate did not sign is refused", func(t *testing.T) {
			// Checked against the root instead of the intermediate: the
			// leaf's signature does not verify under it.
			root, _ := x509.ParseCertificate(rootDER)
			err := load(label, certPath, root)
			if !errors.Is(err, ca.ErrNotAServiceCertificate) {
				t.Fatalf("err = %v, want ErrNotAServiceCertificate", err)
			}
		})

		t.Run("a missing key label is refused", func(t *testing.T) {
			err := load(b.label("no-such-key"), certPath, c.Certificate())
			if !errors.Is(err, ca.ErrKeyNotFound) {
				t.Fatalf("err = %v, want ErrKeyNotFound", err)
			}
		})
	})
}
