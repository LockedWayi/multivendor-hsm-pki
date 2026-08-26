package ca_test

// Sub-task 2.2's tests run against SoftHSM2 only — see the "Decide before
// starting" entry in docs/phases/phase-2-ca-core.md: Phase 1's conformance
// suite already proved VendorAdapter generalizes across two independent
// vendors, so the CA layer, which only ever calls through that interface,
// does not need to re-prove it per test.

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

	"github.com/LockedWayi/hsm-pki-platform/internal/ca"
	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

// newTestSigner provisions a fresh SoftHSM2 token, generates an EC P-256
// key pair on it, and returns a ready-to-use *ca.Signer over that key.
func newTestSigner(t *testing.T) *ca.Signer {
	t.Helper()
	adapter, ws, resolvePIN := newTestAdapter(t)
	ctx := context.Background()

	const keyLabel = "ca-signer-key"
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
	signer := newTestSigner(t)

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
}

func TestSigner_TamperedDigestFailsVerification(t *testing.T) {
	signer := newTestSigner(t)

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
}

func TestSigner_WrongHashRejected(t *testing.T) {
	signer := newTestSigner(t)

	digest := sha256.Sum256([]byte("wrong hash"))
	if _, err := signer.Sign(rand.Reader, digest[:], crypto.SHA512); err == nil {
		t.Fatal("Sign with a mismatched hash function succeeded, want an error")
	}
}

func TestSigner_WrongDigestLengthRejected(t *testing.T) {
	signer := newTestSigner(t)

	if _, err := signer.Sign(rand.Reader, []byte{1, 2, 3}, crypto.SHA256); err == nil {
		t.Fatal("Sign with a short digest succeeded, want an error")
	}
}

// TestSigner_SelfSignedCertificate is sub-task 2.2's own Done-when
// criterion: x509.CreateCertificate produces a certificate signed by an
// HSM-resident key, and cert.CheckSignatureFrom(issuer) accepts it.
func TestSigner_SelfSignedCertificate(t *testing.T) {
	signer := newTestSigner(t)

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
}

func ecdsaVerifyASN1(pub *ecdsa.PublicKey, digest, sig []byte) bool {
	return ecdsa.VerifyASN1(pub, digest, sig)
}
