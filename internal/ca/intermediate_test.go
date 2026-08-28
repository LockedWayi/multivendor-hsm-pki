package ca_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/ca"
	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

// runCeremonyForLoad runs a ceremony and writes its intermediate certificate
// to disk, returning the backend and the path — the starting point every
// LoadIntermediate test needs.
func runCeremonyForLoad(t *testing.T, b *ceremonyBackend) (interCertPath string, result *ca.CeremonyResult) {
	t.Helper()
	result, err := ca.RunCeremony(context.Background(), b.adapter, pk11.SessionOptions{}, testCeremonyParams(b))
	if err != nil {
		t.Fatalf("RunCeremony: %v", err)
	}
	interCertPath = filepath.Join(t.TempDir(), "intermediate.pem")
	writePEM(t, interCertPath, "CERTIFICATE", result.IntermediateCertDER)
	return interCertPath, result
}

func loadParams(b *ceremonyBackend, certPath string) ca.LoadIntermediateParams {
	return ca.LoadIntermediateParams{
		KeyLabel: b.interKeyLabel(),
		CertPath: certPath,
		Curve:    pk11.P256,
		CertTTL:  time.Hour,
	}
}

// TestLoadIntermediate_LoadsCeremonyOutput is the success path: the service
// comes up on exactly what a ceremony produced.
func TestLoadIntermediate_LoadsCeremonyOutput(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		ctx := context.Background()
		certPath, result := runCeremonyForLoad(t, b)

		resolvePIN := func() ([]byte, error) { return []byte(b.interPIN), nil }
		c, err := ca.LoadIntermediate(ctx, b.adapter, b.interWS, pk11.SessionOptions{}, resolvePIN, loadParams(b, certPath))
		if err != nil {
			t.Fatalf("LoadIntermediate: %v", err)
		}
		t.Cleanup(func() { _ = b.adapter.LogoutToken(ctx) })

		if c.Certificate().MaxPathLenZero != true {
			t.Fatal("loaded certificate is not pathlen:0")
		}
		want, err := x509.ParseCertificate(result.IntermediateCertDER)
		if err != nil {
			t.Fatalf("parsing expected intermediate: %v", err)
		}
		if c.Certificate().SerialNumber.Cmp(want.SerialNumber) != 0 {
			t.Fatalf("loaded certificate serial %v, want %v", c.Certificate().SerialNumber, want.SerialNumber)
		}
	})
}

// TestLoadIntermediate_RefusesRootCertificate is the guard this whole phase
// exists for: pointing the online service at a self-signed (root)
// certificate must stop it from starting, not merely warn.
func TestLoadIntermediate_RefusesRootCertificate(t *testing.T) {
	forEachCeremonyBackend(t, func(t *testing.T, b *ceremonyBackend) {
		ctx := context.Background()
		_, result := runCeremonyForLoad(t, b)

		rootPath := filepath.Join(t.TempDir(), "root.pem")
		writePEM(t, rootPath, "CERTIFICATE", result.RootCertDER)

		resolvePIN := func() ([]byte, error) { return []byte(b.interPIN), nil }
		_, err := ca.LoadIntermediate(ctx, b.adapter, b.interWS, pk11.SessionOptions{}, resolvePIN, loadParams(b, rootPath))
		t.Cleanup(func() { _ = b.adapter.LogoutToken(ctx) })

		if err == nil {
			t.Fatal("LoadIntermediate accepted a self-signed root certificate, want an error")
		}
		if !errors.Is(err, ca.ErrRootCertificateRejected) {
			t.Fatalf("error is not ErrRootCertificateRejected: %v", err)
		}
	})
}

// TestLoadIntermediate_RejectsUnsuitableCertificates covers the remaining
// tier constraints, using software-generated certificates so each defect can
// be produced in isolation.
func TestLoadIntermediate_RejectsUnsuitableCertificates(t *testing.T) {
	b := setupSoftHSM2CeremonyBackend(t)
	ctx := context.Background()
	_, _ = runCeremonyForLoad(t, b)

	resolvePIN := func() ([]byte, error) { return []byte(b.interPIN), nil }

	tests := []struct {
		name    string
		cert    func(t *testing.T) []byte
		wantErr error
	}{
		{
			name:    "not a CA at all",
			cert:    func(t *testing.T) []byte { return foreignCertDER(t, false, true) },
			wantErr: ca.ErrNotAnIntermediate,
		},
		{
			name:    "CA without pathlen:0",
			cert:    func(t *testing.T) []byte { return foreignCertDER(t, true, false) },
			wantErr: ca.ErrNotAnIntermediate,
		},
		{
			name: "well-formed intermediate for a different key",
			cert: func(t *testing.T) []byte { return foreignCertDER(t, true, true) },
			// Signed by an unrelated issuer, pathlen:0, IsCA — passes every
			// certificate-shape check and is caught only by the key match.
			wantErr: ca.ErrKeyCertMismatch,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "cert.pem")
			writePEM(t, path, "CERTIFICATE", tc.cert(t))

			_, err := ca.LoadIntermediate(ctx, b.adapter, b.interWS, pk11.SessionOptions{}, resolvePIN, loadParams(b, path))
			if err == nil {
				t.Fatalf("LoadIntermediate accepted %s, want an error", tc.name)
			}
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("error is not %v: %v", tc.wantErr, err)
			}
		})
	}
	_ = b.adapter.LogoutToken(ctx)
}

func TestLoadIntermediate_MissingCertFileFails(t *testing.T) {
	b := setupSoftHSM2CeremonyBackend(t)
	ctx := context.Background()
	resolvePIN := func() ([]byte, error) { return []byte(b.interPIN), nil }

	// No ceremony has run and no file exists. The service must report a
	// configuration error rather than create a CA to fill the gap, which is
	// exactly what the removed Bootstrap would have done.
	_, err := ca.LoadIntermediate(ctx, b.adapter, b.interWS, pk11.SessionOptions{}, resolvePIN,
		loadParams(b, filepath.Join(t.TempDir(), "does-not-exist.pem")))
	t.Cleanup(func() { _ = b.adapter.LogoutToken(ctx) })

	if err == nil {
		t.Fatal("LoadIntermediate with no certificate file succeeded, want an error")
	}
	if !os.IsNotExist(errors.Unwrap(err)) {
		t.Logf("error (acceptable, but check it names the missing file): %v", err)
	}
}

// foreignCertDER builds a certificate signed by an unrelated, software-held
// issuer, with the CA and pathlen properties the caller asks for. It never
// stands in for HSM-backed custody — it exists only to produce certificates
// with specific defects.
func foreignCertDER(t *testing.T, isCA, pathLenZero bool) []byte {
	t.Helper()
	issuerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey (issuer): %v", err)
	}
	issuerTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "foreign issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTmpl, issuerTmpl, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("CreateCertificate (issuer): %v", err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatalf("ParseCertificate (issuer): %v", err)
	}

	subjectKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey (subject): %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "foreign subject"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		BasicConstraintsValid: true,
		IsCA:                  isCA,
	}
	if isCA {
		tmpl.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
		if pathLenZero {
			tmpl.MaxPathLen = 0
			tmpl.MaxPathLenZero = true
		} else {
			tmpl.MaxPathLen = 1
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, issuer, &subjectKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatalf("CreateCertificate (subject): %v", err)
	}
	return der
}
