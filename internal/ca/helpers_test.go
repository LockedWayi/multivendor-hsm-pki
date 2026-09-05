package ca_test

// Shared SoftHSM2 test scaffolding for this package's tests. Sub-task 2.2's
// "Decide before starting" entry in applies
// to every test file here: SoftHSM2 only. Phase 1's conformance suite
// already proved VendorAdapter generalizes across two independent vendors,
// and the CA layer only ever calls through that interface.

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

// newTestAdapter returns the backend's primary token, authenticated, plus a
// PIN resolver for it — the scaffolding a test needs before it can generate
// keys or build a Signer over them.
//
// The token itself comes from internal/hsmtest, so this works identically
// against every configured vendor. It used to provision a SoftHSM2 token
// inline, which is why this package's tests were SoftHSM2-only.
func newTestAdapter(t *testing.T, b *ceremonyBackend) (pk11.VendorAdapter, pk11.Workspace, func() ([]byte, error)) {
	t.Helper()

	// Establish the anchor login the way the service does at startup, so
	// tests driving the adapter directly work against an authenticated
	// token. LoginToken is not idempotent — it reports
	// ErrTokenAlreadyLoggedIn — so a backend already authenticated by an
	// earlier helper in the same test is left alone.
	if !b.adapter.TokenLoggedIn() {
		if err := b.adapter.LoginToken(context.Background(), b.interWS, []byte(b.interPIN), pk11.RoleUser); err != nil {
			t.Fatalf("LoginToken: %v", err)
		}
		t.Cleanup(func() { _ = b.adapter.LogoutToken(context.Background()) })
	}

	resolvePIN := func() ([]byte, error) { return []byte(b.interPIN), nil }
	return b.adapter, b.interWS, resolvePIN
}

// withSession opens a session against ws, runs fn, and closes it. No login:
// newTestAdapter has already established the token's anchor login, which
// every session on that token inherits (internal/pkcs11/tokenlogin.go).
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

// testLeafDistribution is the CDP/AIA pair every test-built CA issues under.
// Issue refuses to sign without one (ca.ErrNoDistributionPoints), which is
// deliberate: a leaf whose revocation cannot be published is not a
// certificate this platform is willing to produce.
func testLeafDistribution() ca.LeafDistribution {
	return ca.LeafDistribution{CRLURL: testLeafCRLURL, IssuerCertURL: testLeafIssuerURL}
}
