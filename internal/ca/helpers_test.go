package ca_test

// Shared scaffolding for this package's token-touching tests. The tokens
// come from internal/hsmtest, so every test runs against every backend.

import (
	"context"
	"testing"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

func requireSoftHSM2(t *testing.T) string {
	t.Helper()
	return hsmtest.RequireSoftHSM2(t)
}

// newTestAdapter returns the backend's primary token, authenticated, plus
// a PIN resolver for it.
func newTestAdapter(t *testing.T, b *ceremonyBackend) (pk11.VendorAdapter, pk11.Workspace, func() ([]byte, error)) {
	t.Helper()

	// The anchor login, as the service establishes it at startup.
	// LoginToken is not idempotent, so an already authenticated backend is
	// left alone.
	if !b.adapter.TokenLoggedIn() {
		if err := b.adapter.LoginToken(context.Background(), b.interWS, []byte(b.interPIN), pk11.RoleUser); err != nil {
			t.Fatalf("LoginToken: %v", err)
		}
		t.Cleanup(func() { _ = b.adapter.LogoutToken(context.Background()) })
	}

	resolvePIN := func() ([]byte, error) { return []byte(b.interPIN), nil }
	return b.adapter, b.interWS, resolvePIN
}

// withSession opens a session against ws, runs fn, and closes it. No
// login: every session inherits the anchor login.
func withSession[T any](t *testing.T, ctx context.Context, adapter pk11.VendorAdapter, ws pk11.Workspace, resolvePIN func() ([]byte, error), fn func(*pk11.Session) (T, error)) (T, error) {
	t.Helper()
	var zero T
	s, err := adapter.OpenSession(ctx, ws, pk11.SessionOptions{})
	if err != nil {
		return zero, err
	}
	defer adapter.CloseSession(ctx, s)
	return fn(s)
}

// testLeafDistribution is the CDP and AIA pair every test-built CA issues
// under. Issue refuses to sign without one.
func testLeafDistribution() ca.LeafDistribution {
	return ca.LeafDistribution{CRLURL: testLeafCRLURL, IssuerCertURL: testLeafIssuerURL}
}
