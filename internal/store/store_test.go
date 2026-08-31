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
		s, err := store.OpenSQLite(t.Context(), path, nil, nil)
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

// messyTime is deliberately awkward: a non-UTC zone and sub-second
// precision. Passing an already-normalized instant is what let the two
// implementations disagree while the shared suite stayed green, so the suite
// now hands them something only a real normalization can flatten.
func messyTime(t *testing.T) time.Time {
	t.Helper()
	loc, err := time.LoadLocation("Asia/Istanbul")
	if err != nil {
		// A tzdata-less environment is not a reason to skip the precision
		// half of the check.
		return time.Now().Add(24 * time.Hour).Add(437 * time.Millisecond)
	}
	return time.Now().In(loc).Add(24 * time.Hour).Add(437 * time.Millisecond)
}

func testRecord(t *testing.T, serial int64, cn string) store.CertRecord {
	t.Helper()
	return store.CertRecord{
		Serial:   big.NewInt(serial),
		Subject:  pkix.Name{CommonName: cn, Organization: []string{"hsm-pki-platform test"}},
		NotAfter: messyTime(t),
		Status:   store.StatusValid,
	}
}

func TestStore_RecordAndGet(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		ctx := t.Context()
		s := b.open(t)
		defer s.Close()

		rec := testRecord(t, 1001, "leaf.example.test")
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
		// Both implementations must return the same normalized instant, not
		// merely "something close to" what was passed in.
		wantNotAfter := store.NormalizeTime(rec.NotAfter)
		if !got.NotAfter.Equal(wantNotAfter) {
			t.Fatalf("NotAfter = %v, want the normalized %v", got.NotAfter, wantNotAfter)
		}
		if got.NotAfter.Location() != time.UTC {
			t.Fatalf("NotAfter is in %v, want UTC — the two implementations must not differ on this", got.NotAfter.Location())
		}
		if got.NotAfter.Nanosecond() != 0 {
			t.Fatalf("NotAfter carries sub-second precision (%v) a CRL cannot express", got.NotAfter)
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
		ctx := t.Context()
		s := b.open(t)
		defer s.Close()

		rec := testRecord(t, 2001, "revoke.example.test")
		if err := s.Record(ctx, rec); err != nil {
			t.Fatalf("Record: %v", err)
		}

		at := messyTime(t)
		if err := s.Revoke(ctx, rec.Serial, store.ReasonKeyCompromise, at); err != nil {
			t.Fatalf("Revoke: %v", err)
		}

		got, ok, err := s.Get(ctx, rec.Serial)
		if err != nil || !ok {
			t.Fatalf("Get after revoke: %v (found=%v)", err, ok)
		}
		if got.Status != store.StatusRevoked {
			t.Fatalf("Status = %q, want %q", got.Status, store.StatusRevoked)
		}
		if got.RevocationReason != store.ReasonKeyCompromise {
			t.Fatalf("RevocationReason = %d, want %d", got.RevocationReason, store.ReasonKeyCompromise)
		}
		wantRevokedAt := store.NormalizeTime(at)
		if !got.RevokedAt.Equal(wantRevokedAt) {
			t.Fatalf("RevokedAt = %v, want the normalized %v", got.RevokedAt, wantRevokedAt)
		}
		if got.RevokedAt.Location() != time.UTC || got.RevokedAt.Nanosecond() != 0 {
			t.Fatalf("RevokedAt = %v is not normalized to UTC seconds", got.RevokedAt)
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
		err := s(t, b).Revoke(t.Context(), big.NewInt(31337), store.ReasonUnspecified, time.Now())
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
		ctx := t.Context()
		st := b.open(t)
		defer st.Close()

		rec := testRecord(t, 3001, "idempotent.example.test")
		if err := st.Record(ctx, rec); err != nil {
			t.Fatalf("Record: %v", err)
		}

		first := time.Now().Add(-time.Hour)
		if err := st.Revoke(ctx, rec.Serial, store.ReasonKeyCompromise, first); err != nil {
			t.Fatalf("first Revoke: %v", err)
		}
		// A second call with a different time and reason must not take.
		if err := st.Revoke(ctx, rec.Serial, store.ReasonSuperseded, time.Now()); err != nil {
			t.Fatalf("second Revoke returned an error instead of succeeding idempotently: %v", err)
		}

		got, _, err := st.Get(ctx, rec.Serial)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if got.RevocationReason != store.ReasonKeyCompromise {
			t.Fatalf("RevocationReason = %d after re-revocation, want the original %d", got.RevocationReason, store.ReasonKeyCompromise)
		}
		if !got.RevokedAt.Equal(store.NormalizeTime(first)) {
			t.Fatalf("RevokedAt = %v after re-revocation, want the original %v", got.RevokedAt, store.NormalizeTime(first))
		}
	})
}

func TestStore_CRLNumberIsStrictlyIncreasing(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		ctx := t.Context()
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

	rec := testRecord(t, 4001, "survives-restart.example.test")
	revokedAt := messyTime(t)

	var beforeCRLNumber *big.Int
	func() {
		st, err := store.OpenSQLite(ctx, path, nil, nil)
		if err != nil {
			t.Fatalf("OpenSQLite (first): %v", err)
		}
		defer st.Close()

		if err := st.Record(ctx, rec); err != nil {
			t.Fatalf("Record: %v", err)
		}
		if err := st.Revoke(ctx, rec.Serial, store.ReasonKeyCompromise, revokedAt); err != nil {
			t.Fatalf("Revoke: %v", err)
		}
		beforeCRLNumber, err = st.NextCRLNumber(ctx)
		if err != nil {
			t.Fatalf("NextCRLNumber (first): %v", err)
		}
	}()

	// The process is gone. Everything below reads only what was persisted.
	st, err := store.OpenSQLite(ctx, path, nil, nil)
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
	if !revoked[0].RevokedAt.Equal(store.NormalizeTime(revokedAt)) {
		t.Fatalf("RevokedAt = %v after restart, want %v", revoked[0].RevokedAt, store.NormalizeTime(revokedAt))
	}
	if revoked[0].RevocationReason != store.ReasonKeyCompromise {
		t.Fatalf("RevocationReason = %d after restart, want %d", revoked[0].RevocationReason, store.ReasonKeyCompromise)
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
	st, err := store.OpenSQLite(ctx, filepath.Join(t.TempDir(), "fresh.db"), nil, nil)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	defer st.Close()

	n, err := st.NextCRLNumber(ctx)
	if err != nil {
		t.Fatalf("NextCRLNumber: %v", err)
	}
	// Bounded dynamically rather than by a hard-coded epoch, so the test
	// asserts "seeded from roughly now" instead of "above a date someone
	// picked once".
	lower := big.NewInt(time.Now().Add(-time.Hour).UnixMilli())
	if n.Cmp(lower) < 0 {
		t.Fatalf("a fresh store's first CRL number is %v, below %v; it must be seeded from the clock so a rebuilt store cannot reissue numbers verifiers already hold", n, lower)
	}
}

// TestStore_ConcurrentUse re-establishes under -race that the store is safe
// under the concurrent issuance load Phase 2.8 set for the service, and that
// concurrency cannot hand out a duplicate CRL number.
func TestStore_ConcurrentUse(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		ctx := t.Context()
		st := b.open(t)
		defer st.Close()

		const workers = 16
		var wg sync.WaitGroup
		errs := make([]error, workers)
		numbers := make([]*big.Int, workers)

		// A start barrier, so every goroutine is already spawned and waiting
		// when the work begins. Without it the first workers finish before
		// the last are scheduled and the test proves far less about
		// contention than it appears to.
		start := make(chan struct{})

		wg.Add(workers)
		for i := 0; i < workers; i++ {
			go func(i int) {
				defer wg.Done()
				<-start
				rec := testRecord(t, int64(10_000+i), "concurrent.example.test")
				if err := st.Record(ctx, rec); err != nil {
					errs[i] = err
					return
				}
				if err := st.Revoke(ctx, rec.Serial, store.ReasonKeyCompromise, time.Now()); err != nil {
					errs[i] = err
					return
				}
				numbers[i], errs[i] = st.NextCRLNumber(ctx)
			}(i)
		}
		close(start)
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

// TestStore_RecordRejectsDuplicateSerial is the regression for the defect
// this suite missed on the first pass: Record used to overwrite an existing
// row, and because an incoming record carries StatusValid, re-recording an
// already-revoked serial silently un-revoked it and dropped it out of the
// CRL — the exact failure this package exists to prevent, reached through a
// different door.
func TestStore_RecordRejectsDuplicateSerial(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		ctx := t.Context()
		st := b.open(t)
		defer st.Close()

		rec := testRecord(t, 5001, "duplicate.example.test")
		if err := st.Record(ctx, rec); err != nil {
			t.Fatalf("Record: %v", err)
		}
		if err := st.Revoke(ctx, rec.Serial, store.ReasonKeyCompromise, time.Now()); err != nil {
			t.Fatalf("Revoke: %v", err)
		}

		if err := st.Record(ctx, rec); !errors.Is(err, store.ErrDuplicateSerial) {
			t.Fatalf("re-recording an existing serial returned %v, want ErrDuplicateSerial", err)
		}

		// And the revocation must be exactly as it was.
		got, ok, err := st.Get(ctx, rec.Serial)
		if err != nil || !ok {
			t.Fatalf("Get: %v (found=%v)", err, ok)
		}
		if got.Status != store.StatusRevoked {
			t.Fatalf("status = %q after a rejected re-Record; the revocation was lost", got.Status)
		}
		revoked, err := st.Revoked(ctx)
		if err != nil {
			t.Fatalf("Revoked: %v", err)
		}
		if len(revoked) != 1 {
			t.Fatalf("Revoked() returns %d entries after a rejected re-Record, want 1", len(revoked))
		}
	})
}

// TestStore_RevokeRejectsInvalidReason keeps a reason code no verifier can
// interpret out of the CRL. Neither crypto/x509 nor the CRL builder checks
// it, so this is the only place it can be caught.
func TestStore_RevokeRejectsInvalidReason(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		ctx := t.Context()
		st := b.open(t)
		defer st.Close()

		rec := testRecord(t, 6001, "bad-reason.example.test")
		if err := st.Record(ctx, rec); err != nil {
			t.Fatalf("Record: %v", err)
		}

		for _, reason := range []store.RevocationReason{
			-1,
			7,   // unassigned in RFC 5280 §5.3.1
			8,   // removeFromCRL: delta-CRL only, not a revocation reason
			11,  // past the assigned range
			999, // what an unvalidated API caller could send
		} {
			if err := st.Revoke(ctx, rec.Serial, reason, time.Now()); !errors.Is(err, store.ErrInvalidRevocationReason) {
				t.Fatalf("Revoke with reason %d returned %v, want ErrInvalidRevocationReason", reason, err)
			}
		}

		// None of them may have taken effect.
		got, _, _ := st.Get(ctx, rec.Serial)
		if got.Status != store.StatusValid {
			t.Fatalf("status = %q after only-rejected revocations, want %q", got.Status, store.StatusValid)
		}
	})
}

// TestStore_ReturnedSerialIsACopy pins that a caller cannot reach into the
// store through the *big.Int it was handed.
func TestStore_ReturnedSerialIsACopy(t *testing.T) {
	forEachBackend(t, func(t *testing.T, b backend) {
		ctx := t.Context()
		st := b.open(t)
		defer st.Close()

		rec := testRecord(t, 7001, "aliasing.example.test")
		original := new(big.Int).Set(rec.Serial)
		if err := st.Record(ctx, rec); err != nil {
			t.Fatalf("Record: %v", err)
		}

		// Mutating the caller's own serial must not reach the store.
		rec.Serial.Add(rec.Serial, big.NewInt(1))

		got, ok, err := st.Get(ctx, original)
		if err != nil || !ok {
			t.Fatalf("the stored record moved when the caller mutated its serial: %v (found=%v)", err, ok)
		}
		// And mutating what Get returned must not reach it either.
		got.Serial.Add(got.Serial, big.NewInt(1))
		if _, ok, _ := st.Get(ctx, original); !ok {
			t.Fatal("the stored record moved when the value returned by Get was mutated")
		}
	})
}

// TestSQLite_CRLNumberFloorRaisesASeed covers the operator escape hatch for
// the one case the clock seed cannot cover alone: a rebuilt store on a host
// whose clock has moved backwards, where an operator who knows the last
// issued number supplies it.
func TestSQLite_CRLNumberFloorRaisesASeed(t *testing.T) {
	ctx := t.Context()
	floor := new(big.Int).Add(big.NewInt(time.Now().UnixMilli()), big.NewInt(1_000_000_000))

	st, err := store.OpenSQLite(ctx, filepath.Join(t.TempDir(), "floor.db"), nil, floor)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	defer st.Close()

	n, err := st.NextCRLNumber(ctx)
	if err != nil {
		t.Fatalf("NextCRLNumber: %v", err)
	}
	if n.Cmp(floor) < 0 {
		t.Fatalf("seeded CRL number %v is below the configured floor %v", n, floor)
	}
}

// TestSQLite_CRLNumberFloorDoesNotTouchAnExistingCounter: the floor seeds,
// it does not reset. An operator setting it on a healthy store must not
// cause the sequence to jump or, worse, restart.
func TestSQLite_CRLNumberFloorDoesNotTouchAnExistingCounter(t *testing.T) {
	ctx := t.Context()
	path := filepath.Join(t.TempDir(), "existing.db")

	first, err := store.OpenSQLite(ctx, path, nil, nil)
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	seeded, err := first.NextCRLNumber(ctx)
	if err != nil {
		t.Fatalf("NextCRLNumber: %v", err)
	}
	first.Close()

	floor := new(big.Int).Add(seeded, big.NewInt(1_000_000_000))
	second, err := store.OpenSQLite(ctx, path, nil, floor)
	if err != nil {
		t.Fatalf("OpenSQLite (with floor): %v", err)
	}
	defer second.Close()

	next, err := second.NextCRLNumber(ctx)
	if err != nil {
		t.Fatalf("NextCRLNumber: %v", err)
	}
	if want := new(big.Int).Add(seeded, big.NewInt(1)); next.Cmp(want) != 0 {
		t.Fatalf("CRL number = %v after reopening with a floor, want %v — the floor must seed, not reset", next, want)
	}
}
