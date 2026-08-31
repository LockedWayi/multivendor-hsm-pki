package api_test

// Every test in this package runs against every backend the environment
// provides, through internal/hsmtest (CLAUDE.md §2.4). Phase 2 ran them
// against SoftHSM2 alone; that decision is superseded — see the banner on
// docs/phases/phase-2-ca-core.md.

import (
	"context"
	"crypto/x509/pkix"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/api"
	"github.com/LockedWayi/hsm-pki-platform/internal/ca"
	"github.com/LockedWayi/hsm-pki-platform/internal/hsmtest"
	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

// newTestCA provisions two SoftHSM2 tokens, runs a real root ceremony over
// them, and returns the **intermediate** CA the service is built on, plus
// the adapter and workspace callers need for the /readyz probe and the
// public root artifacts the server republishes.
//
// It used to bootstrap a self-signed root, matching what the service did
// before Phase 3b. That configuration is now refused at startup
// (ca.LoadIntermediate), so testing the HTTP surface against one would
// exercise a deployment this platform rejects.
func newTestCA(t *testing.T, b *hsmtest.Backend) (*ca.CA, pk11.VendorAdapter, pk11.Workspace, api.RootArtifacts) {
	t.Helper()
	return newTestCAAt(t, b, testBaseURL)
}

// testBaseURL stands in for a deployment's externally reachable origin in
// the tests that never fetch what the URLs point at. The tests that do —
// the ones proving a leaf's CDP and AIA actually resolve — pass the live
// httptest listener's address to newTestCAAt instead, because a placeholder
// would prove nothing about whether the paths match the routes.
const testBaseURL = "https://pki.example.test"

// newTestCAAt runs a real two-token ceremony on the given backend and
// returns the intermediate CA the service is built on, plus the adapter and
// workspace the /readyz probe needs and the public root artifacts the
// server republishes.
//
// The tokens come from internal/hsmtest, so every test in this package runs
// against every configured vendor (CLAUDE.md §2.4). This helper used to
// provision SoftHSM2 tokens inline, which is why the whole HTTP surface was
// only ever exercised against one implementation.
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

	// Load it exactly the way cmd/hsm-pki-server does, so these tests
	// exercise the real startup path rather than a shortcut around it.
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
