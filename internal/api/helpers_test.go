package api_test

// Every test in this package runs against every backend the environment
// provides, through internal/hsmtest.

import (
	"context"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/api"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// newTestCA runs a real root ceremony on the backend's two tokens and
// returns the intermediate CA the service is built on, plus what the
// /readyz probe and the root artifact endpoints need.
func newTestCA(t *testing.T, b *hsmtest.Backend) (*ca.CA, pk11.VendorAdapter, pk11.Workspace, api.RootArtifacts) {
	t.Helper()
	return newTestCAAt(t, b, testBaseURL)
}

// testBaseURL stands in for a deployment's origin in the tests that never
// fetch what the URLs point at. The tests that do pass the live httptest
// listener's address to newTestCAAt.
const testBaseURL = "https://pki.example.test"

// newTestCAAt is newTestCA with the base URL the leaf distribution points
// are built from.
func newTestCAAt(t *testing.T, b *hsmtest.Backend, baseURL string) (*ca.CA, pk11.VendorAdapter, pk11.Workspace, api.RootArtifacts) {
	t.Helper()
	ctx := context.Background()

	interKeyLabel := b.Label("api-inter-key-v1")
	result, err := ca.RunCeremony(ctx, b.Adapter, pk11.SessionOptions{}, ca.CeremonyParams{
		RootWorkspace: b.Secondary,
		RootPIN:       b.SecondaryPINFunc(),
		RootKeyLabel:  b.Label("api-root-key-v1"),
		RootSubject:   pkix.Name{CommonName: "hsm-pki-platform api test Root CA"},
		RootCurve:     pk11.P256,
		RootCRLURL:    "http://pki.example.test/root.crl",
		RootCertURL:   "http://pki.example.test/root.crt",

		IntermediateWorkspace: b.Primary,
		IntermediatePIN:       b.PrimaryPINFunc(),
		IntermediateKeyLabel:  interKeyLabel,
		IntermediateSubject:   pkix.Name{CommonName: "hsm-pki-platform api test Intermediate CA"},
		IntermediateCurve:     pk11.P256,
	})
	if err != nil {
		t.Fatalf("RunCeremony: %v", err)
	}

	interCertPath := filepath.Join(t.TempDir(), "intermediate.pem")
	if err := os.WriteFile(interCertPath,
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: result.IntermediateCertDER}), 0644); err != nil {
		t.Fatalf("WriteFile(intermediate): %v", err)
	}

	// Loaded the way cmd/hsm-pki-server does.
	c, err := ca.LoadIntermediate(ctx, b.Adapter, b.Primary, pk11.SessionOptions{}, b.PrimaryPINFunc(), ca.LoadIntermediateParams{
		KeyLabel:     interKeyLabel,
		CertPath:     interCertPath,
		Curve:        pk11.P256,
		CertTTL:      time.Hour,
		Distribution: api.LeafDistributionFor(baseURL),
	})
	if err != nil {
		t.Fatalf("LoadIntermediate: %v", err)
	}
	t.Cleanup(func() { _ = b.Adapter.LogoutToken(ctx) })

	return c, b.Adapter, b.Primary, api.RootArtifacts{CertDER: result.RootCertDER, CRLDER: result.RootCRLDER}
}
