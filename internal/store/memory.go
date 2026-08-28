package store

import (
	"context"
	"math/big"
	"sync"
	"time"
)

// Memory is an in-memory Store. It is what tests run against, so the suite
// needs no filesystem and no SQL driver.
//
// It is not a fallback for the service. A process restart loses everything
// it holds, and losing revocations is a security regression rather than a
// durability inconvenience — which is precisely why SQLite exists alongside
// it (see the package doc). Nothing in cmd/ constructs this.
type Memory struct {
	mu        sync.Mutex
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
	// Store an explicit copy rather than &rec. Taking the address of a
	// by-value parameter is safe in Go, but it reads as though the caller's
	// variable is being aliased and the next reader should not have to work
	// out that it is not. Serial stays shared — a *big.Int nobody mutates
	// after issuance.
	stored := rec
	m.records[rec.Serial.String()] = &stored
	return nil
}

// Get implements Store.
func (m *Memory) Get(_ context.Context, serial *big.Int) (CertRecord, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[serial.String()]
	if !ok {
		return CertRecord{}, false, nil
	}
	return *rec, true, nil
}

// Revoke implements Store.
func (m *Memory) Revoke(_ context.Context, serial *big.Int, reason int, at time.Time) error {
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
	rec.RevokedAt = at
	rec.RevocationReason = reason
	return nil
}

// Revoked implements Store.
func (m *Memory) Revoked(_ context.Context) ([]CertRecord, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []CertRecord
	for _, rec := range m.records {
		if rec.Status == StatusRevoked {
			out = append(out, *rec)
		}
	}
	return out, nil
}

// NextCRLNumber implements Store.
//
// The seeding rule matches SQLite's, so the two implementations cannot
// disagree about it: the first number comes from the wall clock in Unix
// milliseconds, and every later one is the previous plus one. See
// SQLite.NextCRLNumber for why the clock seeds rather than starting at 1.
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

// Len reports how many records the store holds, of any status.
//
// It is deliberately on Memory rather than on Store. Tests need to assert
// "nothing was recorded" after a rejected request, which needs a count of
// everything; the service never does, because CRL generation wants only the
// revoked ones. Putting a List-everything method on the interface to serve a
// test would make every implementation carry an operation the product does
// not use — and would push SQLite into materializing rows nobody reads.
func (m *Memory) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.records)
}

// seedCRLNumber produces the first CRL number a fresh store hands out.
//
// Unix milliseconds rather than 1, because "fresh store" and "fresh CA" are
// not the same event. A store rebuilt from scratch — a new deployment, a
// lost volume, a restored host — would otherwise restart the sequence at 1
// while verifiers still hold a CRL numbered far higher, and RFC 5280 §5.2.3
// means those verifiers then ignore every CRL this CA issues afterward.
// Seeding from the clock guarantees the new sequence starts above the old
// one without needing to have kept anything.
//
// What this depends on is the clock not stepping backwards across a rebuild;
// NTP makes that not happen in practice, and the alternative — a number that
// must be remembered to be correct — is exactly what a rebuilt store has
// lost.
func seedCRLNumber(now time.Time) *big.Int {
	ms := now.UnixMilli()
	if ms < 1 {
		// A clock at or before the Unix epoch is a broken environment, not
		// a case to model faithfully. RFC 5280 requires a positive number.
		return big.NewInt(1)
	}
	return big.NewInt(ms)
}
