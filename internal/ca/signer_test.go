package ca_test

// Signer tests. Every one runs against every backend the environment
// provides.

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// newTestSigner generates an EC P-256 key pair on the backend's primary
// token and returns a *ca.Signer over it. The label is run-scoped.
func newTestSigner(t *testing.T, b *ceremonyBackend) *ca.Signer {
	t.Helper()
	adapter, ws, resolvePIN := newTestAdapter(t, b)
	ctx := context.Background()

	keyLabel := b.label("signer-key")
	_, err := withSession(t, ctx, adapter, ws, resolvePIN, func(s *pk11.Session) (struct{}, error) {
		_, err := adapter.GenerateKeyPair(ctx, s, pk11.KeyPairRequest{
			Curve: pk11.P256, Label: keyLabel, Sign: true, Verify: true,
		})
		return struct{}{}, err
	})
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}

	signer, err := ca.NewSigner(ctx, adapter, ws, pk11.SessionOptions{}, keyLabel, pk11.P256)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return signer
}

func TestSigner_RoundTrip(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		signer := newTestSigner(t, b)

		digest := sha256.Sum256([]byte("hsm-pki-platform phase 2 signer"))
		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}

		pub, ok := signer.Public().(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("Public() = %T, want *ecdsa.PublicKey", signer.Public())
		}
		if !ecdsaVerifyASN1(pub, digest[:], sig) {
			t.Fatal("crypto/ecdsa rejected the signer's own signature")
		}
	})
}

func TestSigner_TamperedDigestFailsVerification(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		signer := newTestSigner(t, b)

		digest := sha256.Sum256([]byte("hsm-pki-platform phase 2 signer"))
		sig, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}

		pub := signer.Public().(*ecdsa.PublicKey)
		tampered := digest
		tampered[0] ^= 0xFF
		if ecdsaVerifyASN1(pub, tampered[:], sig) {
			t.Fatal("crypto/ecdsa accepted a signature over a tampered digest")
		}
	})
}

func TestSigner_WrongHashRejected(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		signer := newTestSigner(t, b)

		digest := sha256.Sum256([]byte("wrong hash"))
		if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA512); err == nil {
			t.Fatal("Sign with a mismatched hash function succeeded, want an error")
		}
	})
}

func TestSigner_WrongDigestLengthRejected(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		signer := newTestSigner(t, b)

		if _, err := signer.Sign(rand.Reader, []byte{1, 2, 3}, crypto.SHA256); err == nil {
			t.Fatal("Sign with a short digest succeeded, want an error")
		}
	})
}

// TestSigner_SelfSignedCertificate: x509.CreateCertificate produces a
// certificate signed by a key on the token, and CheckSignatureFrom
// accepts it.
func TestSigner_SelfSignedCertificate(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		signer := newTestSigner(t, b)

		template := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "hsm-pki-platform test root"},
			NotBefore:             time.Now().Add(-time.Minute),
			NotAfter:              time.Now().Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}

		der, err := x509.CreateCertificate(rand.Reader, template, template, signer.Public(), signer)
		if err != nil {
			t.Fatalf("x509.CreateCertificate: %v", err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("x509.ParseCertificate: %v", err)
		}
		if err := cert.CheckSignatureFrom(cert); err != nil {
			t.Fatalf("CheckSignatureFrom(self): %v", err)
		}
	})
}

func ecdsaVerifyASN1(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	return ecdsa.VerifyASN1(pub, digest, sig)
}
