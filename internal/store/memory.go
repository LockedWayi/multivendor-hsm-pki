package store

import (
	"context"
	"fmt"
	"math/big"
	"sync"
	"time"
)

// Memory is an in-memory Store for tests. It is not a fallback for the
// service: a restart loses everything, revocations included. Nothing in
// cmd/ constructs it.
type Memory struct {
	// RWMutex: Get, Revoked and Len are read-only and are what a parallel
	// test suite calls most.
	mu        sync.RWMutex
	records   map[string]*CertRecord // keyed by CertRecord.Serial.String()
	crlNumber *big.Int
}

// NewMemory returns an empty in-memory store.
func NewMemory() *Memory {
	return &Memory{records: make(map[string]*CertRecord)}
}

// Record implements Store.
func (m *Memory) Record(_ context.Context, rec CertRecord) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := rec.Serial.String()
	if _, exists := m.records[key]; exists {
		return ErrDuplicateSerial
	}
	stored := copyRecord(rec)
	m.records[key] = &stored
	return nil
}

// copyRecord returns a copy whose Serial is a new big.Int, so the store's
// contents cannot be changed through a pointer the caller still holds.
func copyRecord(rec CertRecord) CertRecord {
	out := rec
	if rec.Serial != nil {
		out.Serial = new(big.Int).Set(rec.Serial)
	}
	out.NotAfter = NormalizeTime(rec.NotAfter)
	if !rec.RevokedAt.IsZero() {
		out.RevokedAt = NormalizeTime(rec.RevokedAt)
	}
	return out
}

// Get implements Store.
func (m *Memory) Get(_ context.Context, serial *big.Int) (CertRecord, bool, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	rec, ok := m.records[serial.String()]
	if !ok {
		return CertRecord{}, false, nil
	}
	return copyRecord(*rec), true, nil
}

// Revoke implements Store.
func (m *Memory) Revoke(_ context.Context, serial *big.Int, reason RevocationReason, at time.Time) error {
	if !reason.Valid() {
		return fmt.Errorf("%w: %d", ErrInvalidRevocationReason, reason)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[serial.String()]
	if !ok {
		return ErrCertNotFound
	}
	if rec.Status == StatusRevoked {
		return nil
	}
	rec.Status = StatusRevoked
	rec.RevokedAt = NormalizeTime(at)
	rec.RevocationReason = reason
	return nil
}

// Revoked implements Store.
func (m *Memory) Revoked(_ context.Context) ([]CertRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []CertRecord
	for _, rec := range m.records {
		if rec.Status == StatusRevoked {
			out = append(out, copyRecord(*rec))
		}
	}
	return out, nil
}

// NextCRLNumber implements Store. The seeding rule matches SQLite's: the
// first number comes from the wall clock in Unix milliseconds, every later
// one is the previous plus one. See seedCRLNumber.
func (m *Memory) NextCRLNumber(_ context.Context) (*big.Int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.crlNumber == nil {
		m.crlNumber = seedCRLNumber(time.Now())
		return new(big.Int).Set(m.crlNumber), nil
	}
	m.crlNumber = new(big.Int).Add(m.crlNumber, big.NewInt(1))
	return new(big.Int).Set(m.crlNumber), nil
}

// Close implements Store. There is nothing to release.
func (m *Memory) Close() error { return nil }

// Len reports how many records the store holds, of any status. It is on
// Memory and not on Store: tests need it, the service does not, and SQLite
// should not materialize rows nobody reads.
func (m *Memory) Len() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.records)
}

// seedCRLNumber produces the first CRL number a fresh store hands out:
// Unix milliseconds, not 1. A store rebuilt from scratch would otherwise
// restart at 1 while verifiers hold a CRL numbered far higher, and RFC
// 5280 §5.2.3 lets them ignore every later CRL. The clock seed starts the
// new sequence above the old one without having kept anything. It depends
// on the clock not stepping backwards across a rebuild.
func seedCRLNumber(now time.Time) *big.Int {
	ms := now.UnixMilli()
	if ms < 1 {
		// A clock at or before the Unix epoch is a broken environment. RFC
		// 5280 requires a positive number.
		return big.NewInt(1)
	}
	return big.NewInt(ms)
}
