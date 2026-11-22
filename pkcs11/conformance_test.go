package pkcs11_test

import (
	"context"
	"testing"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/hsmtest"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/pkcs11"
	"github.com/LockedWayi/multivendor-hsm-pki/pkcs11/conformance"
)

// TestConformance runs package conformance against every backend the
// internal/hsmtest registry provides, in its single-token shape.
// SoftHSM2 is always present in the dev container and carries CI.
// ProtectServer runs when PROTECTSERVER_MODULE is set and Luna when
// LUNA_MODULE is; each skips with its module variable unset and fails with
// it set and the rest of its variables missing.
//
// It lives here rather than in package conformance so that the coverage
// it produces is counted against this package.
func TestConformance(t *testing.T) {
	hsmtest.ForEachSingle(t, func(t *testing.T, s *hsmtest.Single) {
		conformance.Run(t, conformance.Target{
			Name:      s.Name,
			Adapter:   s.Adapter,
			Workspace: s.Workspace,
			PIN:       s.PIN,
			WrongPIN:  s.WrongPIN,
			Role:      s.Role,
			Reopen:    s.Reopen,
			RunID:     s.RunID,
		})
	})
}

// TestCloseSession_AfterTheJanitorDoesNotCloseAnother runs on every
// backend, like the suite, but stays out of package conformance: it
// drives the janitor through hooks only this package's tests can reach.
//
// A session the janitor reclaimed is closed already. Its owner closing it
// afterwards must not reach the module: a module that reuses the freed
// handle has given it to another session by then, and closing it again
// would close that one.
func TestCloseSession_AfterTheJanitorDoesNotCloseAnother(t *testing.T) {
	hsmtest.ForEachSingle(t, func(t *testing.T, s *hsmtest.Single) {
		ctx := context.Background()
		expired, err := s.Adapter.OpenSession(ctx, s.Workspace, pk11.SessionOptions{IdleTimeout: time.Millisecond, MaxTTL: time.Hour})
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
		pk11.SweepExpiredNow(s.Adapter)

		live, err := s.Adapter.OpenSession(ctx, s.Workspace, pk11.SessionOptions{})
		if err != nil {
			t.Fatalf("OpenSession: %v", err)
		}
		defer func() { _ = s.Adapter.CloseSession(ctx, live) }()
		t.Logf("handle reused by the next session: %v", pk11.HandleOf(live) == pk11.HandleOf(expired))

		if err := s.Adapter.CloseSession(ctx, expired); err != nil {
			t.Fatalf("closing a session the janitor reclaimed = %v, want nil", err)
		}
		if _, err := s.Adapter.GenerateRandom(ctx, live, 8); err != nil {
			t.Fatalf("the live session after another's late close = %v; the late close reached its handle", err)
		}
	})
}
