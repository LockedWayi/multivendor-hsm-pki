package store_test

// One suite, both implementations — the same discipline internal/pkcs11's
// conformance suite uses, for the same reason. Memory is what the rest of
// the repository's tests run against, so any behaviour it does not share
// with SQLite is a trap: a test suite that passes against the fake and a
// service that behaves differently against the real store is worse than
// having no fake at all.

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/store"
)

// backend names one implementation and how to build it. reopen returns a
// fresh handle to the *same* underlying state where that is meaningful, and
// nil where it is not — Memory has no state to reopen, which is exactly the
// property the restart tests exist to distinguish.
type backend struct {
	name   string
	open   func(t *testing.T) store.Store
	reopen func(t *testing.T) store.Store // nil for stores that do not persist
}

func backends(t *testing.T) []backend {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "ca.db")

	openSQLite := func(t *testing.T) store.Store {
		t.Helper()
		s, err := store.OpenSQLite(context.Background(), path, nil)
		if err != nil {
			t.Fatalf("OpenSQLite: %v", err)
		}
		return s
	}

	return []backend{
		{
			name: "Memory",
			open: func(t *testing.T) store.Store { return store.NewMemory() },
		},
		{
			name:   "SQLite",
			open:   openSQLite,
			reopen: openSQLite,
		},
	}
}

func forEachBackend(t *testing.T, fn func(t *testing.T, b backend)) {
	t.Helper()
	for _, b := range backends(t) {
		b := b
		t.Run(b.name, func(t *testing.T) { fn(t, b) })
	}
}

func testRecord(serial int64, cn string) store.CertRecord {
	return store.CertRecord{
		Serial:   big.NewInt(serial),
		Subject:  pkix.Name{CommonName: cn, Organization: []string{"hsm-pki-platform test"}},
		NotAfter: time.Now().Add(24 * time.Hour).Truncate(time.Second).UTC(),
		Status:   store.StatusValid,
	}
}

func TestStore_RecordAndGet(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		ctx := context.Background()
		s := b.open(t)
		defer s.Close()

		rec := testRecord(1001, "leaf.example.test")
		if err := s.Record(ctx, rec); err != nil {
			t.Fatalf("Record: %v", err)
		}

		got, ok, err := s.Get(ctx, rec.Serial)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !ok {
			t.Fatal("Get reported the record as absent immediately after Record")
		}
		if got.Serial.Cmp(rec.Serial) != 0 {
			t.Fatalf("serial = %v, want %v", got.Serial, rec.Serial)
		}
		// The subject must survive the round trip intact, not merely
		// approximately: this is the record of what the CA actually issued.
		if got.Subject.CommonName != rec.Subject.CommonName {
			t.Fatalf("CommonName = %q, want %q", got.Subject.CommonName, rec.Subject.CommonName)
		}
		if len(got.Subject.Organization) != 1 || got.Subject.Organization[0] != rec.Subject.Organization[0] {
			t.Fatalf("Organization = %v, want %v", got.Subject.Organization, rec.Subject.Organization)
		}
		if !got.NotAfter.Equal(rec.NotAfter) {
			t.Fatalf("NotAfter = %v, want %v", got.NotAfter, rec.NotAfter)
		}
		if got.Status != store.StatusValid {
			t.Fatalf("Status = %q, want %q", got.Status, store.StatusValid)
		}
	})
}

func TestStore_GetUnknownSerialIsNotAnError(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		s := b.open(t)
		defer s.Close()

		_, ok, err := s.Get(context.Background(), big.NewInt(999999))
		if err != nil {
			t.Fatalf("Get on an unknown serial returned an error: %v", err)
		}
		if ok {
			t.Fatal("Get reported a record for a serial that was never issued")
		}
	})
}

func TestStore_Revoke(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		ctx := context.Background()
		s := b.open(t)
		defer s.Close()

		rec := testRecord(2001, "revoke.example.test")
		if err := s.Record(ctx, rec); err != nil {
			t.Fatalf("Record: %v", err)
		}

		at := time.Now().Truncate(time.Second).UTC()
		if err := s.Revoke(ctx, rec.Serial, 1, at); err != nil {
			t.Fatalf("Revoke: %v", err)
		}

		got, ok, err := s.Get(ctx, rec.Serial)
		if err != nil || !ok {
			t.Fatalf("Get after revoke: %v (found=%v)", err, ok)
		}
		if got.Status != store.StatusRevoked {
			t.Fatalf("Status = %q, want %q", got.Status, store.StatusRevoked)
		}
		if got.RevocationReason != 1 {
			t.Fatalf("RevocationReason = %d, want 1", got.RevocationReason)
		}
		if !got.RevokedAt.Equal(at) {
			t.Fatalf("RevokedAt = %v, want %v", got.RevokedAt, at)
		}

		revoked, err := s.Revoked(ctx)
		if err != nil {
			t.Fatalf("Revoked: %v", err)
		}
		if len(revoked) != 1 || revoked[0].Serial.Cmp(rec.Serial) != 0 {
			t.Fatalf("Revoked() = %v, want exactly the revoked serial", revoked)
		}
	})
}

func TestStore_RevokeUnknownSerialFails(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		err := s(t, b).Revoke(context.Background(), big.NewInt(31337), 0, time.Now())
		if !errors.Is(err, store.ErrCertNotFound) {
			t.Fatalf("Revoke on an unknown serial returned %v, want ErrCertNotFound", err)
		}
	})
}

// TestStore_RevokeIsIdempotent pins the contract that a retried revocation
// succeeds without rewriting when or why the certificate was revoked. That
// original record is what an incident review reads.
func TestStore_RevokeIsIdempotent(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		ctx := context.Background()
		st := b.open(t)
		defer st.Close()

		rec := testRecord(3001, "idempotent.example.test")
		if err := st.Record(ctx, rec); err != nil {
			t.Fatalf("Record: %v", err)
		}

		first := time.Now().Add(-time.Hour).Truncate(time.Second).UTC()
		if err := st.Revoke(ctx, rec.Serial, 1, first); err != nil {
			t.Fatalf("first Revoke: %v", err)
		}
		// A second call with a different time and reason must not take.
		if err := st.Revoke(ctx, rec.Serial, 4, time.Now()); err != nil {
			t.Fatalf("second Revoke returned an error instead of succeeding idempotently: %v", err)
		}

		got, _, err := st.Get(ctx, rec.Serial)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.RevocationReason != 1 {
			t.Fatalf("RevocationReason = %d after re-revocation, want the original 1", got.RevocationReason)
		}
		if !got.RevokedAt.Equal(first) {
			t.Fatalf("RevokedAt = %v after re-revocation, want the original %v", got.RevokedAt, first)
		}
	})
}

func TestStore_CRLNumberIsStrictlyIncreasing(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		ctx := context.Background()
		st := b.open(t)
		defer st.Close()

		prev := big.NewInt(0)
		for i := 0; i < 5; i++ {
			n, err := st.NextCRLNumber(ctx)
			if err != nil {
				t.Fatalf("NextCRLNumber: %v", err)
			}
			if n.Sign() <= 0 {
				t.Fatalf("CRL number %v is not positive (RFC 5280 §5.2.3)", n)
			}
			if n.Cmp(prev) <= 0 {
				t.Fatalf("CRL number %v is not greater than the previous %v", n, prev)
			}
			prev = n
		}
	})
}

// TestSQLite_RevocationSurvivesRestart is sub-task 3b.3's own Done-when
// criterion. It is SQLite-only by nature: it asserts the exact property
// Memory does not have, which is why the service never runs on Memory.
func TestSQLite_RevocationSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "ca.db")

	rec := testRecord(4001, "survives-restart.example.test")
	revokedAt := time.Now().Truncate(time.Second).UTC()

	var beforeCRLNumber *big.Int
	func() {
		st, err := store.OpenSQLite(ctx, path, nil)
		if err != nil {
			t.Fatalf("OpenSQLite (first): %v", err)
		}
		defer st.Close()

		if err := st.Record(ctx, rec); err != nil {
			t.Fatalf("Record: %v", err)
		}
		if err := st.Revoke(ctx, rec.Serial, 1, revokedAt); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		beforeCRLNumber, err = st.NextCRLNumber(ctx)
		if err != nil {
			t.Fatalf("NextCRLNumber (first): %v", err)
		}
	}()

	// The process is gone. Everything below reads only what was persisted.
	st, err := store.OpenSQLite(ctx, path, nil)
	if err != nil {
		t.Fatalf("OpenSQLite (after restart): %v", err)
	}
	defer st.Close()

	revoked, err := st.Revoked(ctx)
	if err != nil {
		t.Fatalf("Revoked after restart: %v", err)
	}
	if len(revoked) != 1 {
		t.Fatalf("after restart the store holds %d revoked certificates, want 1 — a revoked certificate reappearing as valid is a security regression", len(revoked))
	}
	if revoked[0].Serial.Cmp(rec.Serial) != 0 {
		t.Fatalf("revoked serial = %v, want %v", revoked[0].Serial, rec.Serial)
	}
	if !revoked[0].RevokedAt.Equal(revokedAt) {
		t.Fatalf("RevokedAt = %v after restart, want %v", revoked[0].RevokedAt, revokedAt)
	}
	if revoked[0].RevocationReason != 1 {
		t.Fatalf("RevocationReason = %d after restart, want 1", revoked[0].RevocationReason)
	}

	afterCRLNumber, err := st.NextCRLNumber(ctx)
	if err != nil {
		t.Fatalf("NextCRLNumber (after restart): %v", err)
	}
	if afterCRLNumber.Cmp(beforeCRLNumber) <= 0 {
		t.Fatalf("CRL number %v after restart is not greater than %v before it; a verifier holding the earlier CRL would ignore every later one (RFC 5280 §5.2.3)",
			afterCRLNumber, beforeCRLNumber)
	}
}

// TestSQLite_CRLNumberSeedsAboveAClockValue documents the rebuild case: a
// store that was lost and recreated must not restart the sequence at 1,
// because verifiers still hold the numbers the old store issued.
func TestSQLite_CRLNumberSeedsAboveAClockValue(t *testing.T) {
	ctx := context.Background()
	st, err := store.OpenSQLite(ctx, filepath.Join(t.TempDir(), "fresh.db"), nil)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	defer st.Close()

	n, err := st.NextCRLNumber(ctx)
	if err != nil {
		t.Fatalf("NextCRLNumber: %v", err)
	}
	// Comfortably above 1, and in the region a millisecond clock produces.
	if n.Cmp(big.NewInt(1_600_000_000_000)) < 0 {
		t.Fatalf("a fresh store's first CRL number is %v; it must be seeded from the clock so a rebuilt store cannot reissue numbers verifiers already hold", n)
	}
}

// TestStore_ConcurrentUse re-establishes under -race that the store is safe
// under the concurrent issuance load Phase 2.8 set for the service, and that
// concurrency cannot hand out a duplicate CRL number.
func TestStore_ConcurrentUse(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		ctx := context.Background()
		st := b.open(t)
		defer st.Close()

		const workers = 16
		var wg sync.WaitGroup
		errs := make([]error, workers)
		numbers := make([]*big.Int, workers)

		wg.Add(workers)
		for i := 0; i < workers; i++ {
			go func(i int) {
				defer wg.Done()
				rec := testRecord(int64(10_000+i), "concurrent.example.test")
				if err := st.Record(ctx, rec); err != nil {
					errs[i] = err
					return
				}
				if err := st.Revoke(ctx, rec.Serial, 1, time.Now()); err != nil {
					errs[i] = err
					return
				}
				numbers[i], errs[i] = st.NextCRLNumber(ctx)
			}(i)
		}
		wg.Wait()

		seen := make(map[string]bool, workers)
		for i := range errs {
			if errs[i] != nil {
				t.Fatalf("worker %d: %v", i, errs[i])
			}
			key := numbers[i].String()
			if seen[key] {
				t.Fatalf("CRL number %s was handed out twice; a verifier can then ignore every later CRL (RFC 5280 §5.2.3)", key)
			}
			seen[key] = true
		}

		revoked, err := st.Revoked(ctx)
		if err != nil {
			t.Fatalf("Revoked: %v", err)
		}
		if len(revoked) != workers {
			t.Fatalf("store holds %d revoked certificates, want %d", len(revoked), workers)
		}
	})
}

// s opens a backend and registers its cleanup, for the one-liner tests.
func s(t *testing.T, b backend) store.Store {
	t.Helper()
	st := b.open(t)
	t.Cleanup(func() { st.Close() })
	return st
}
