package api

import (
	"crypto/x509/pkix"
	"math/big"
	"sync"
	"time"
)

// Status is a certificate's lifecycle state in the Registry.
type Status string

const (
	StatusValid   Status = "valid"
	StatusRevoked Status = "revoked"
)

// CertRecord is what the Registry remembers about one issued certificate.
// Phase 2 keeps this in memory only — persistent storage is out of scope
// here (docs/phases/phase-2-ca-core.md) — so the record does not survive a
// restart; it exists to answer "what has this CA issued" and, from
// sub-task 2.5 on, "what has it revoked" within one process's lifetime.
type CertRecord struct {
	Serial   *big.Int
	Subject  pkix.Name
	NotAfter time.Time
	Status   Status

	RevokedAt        time.Time
	RevocationReason int // CRLReason code (RFC 5280 §5.3.1), meaningful only when Status == StatusRevoked
}

// Registry is an in-memory, concurrency-safe record of certificates this
// service has issued.
type Registry struct {
	mu      sync.Mutex
	records map[string]*CertRecord // keyed by CertRecord.Serial.String()
}

// NewRegistry returns an empty Registry.
func NewRegistry() *Registry {
	return &Registry{records: make(map[string]*CertRecord)}
}

// Record stores rec, keyed by its serial number. A second Record call for
// the same serial overwrites the first — serials are unique per Issue call
// (ca.GenerateSerial), so this should not happen in practice, but Record
// does not itself enforce it.
func (r *Registry) Record(rec CertRecord) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.records[rec.Serial.String()] = &rec
}

// Get returns the record for serial, if one exists.
func (r *Registry) Get(serial *big.Int) (CertRecord, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.records[serial.String()]
	if !ok {
		return CertRecord{}, false
	}
	return *rec, true
}

// All returns every record currently in the registry, in no particular
// order.
func (r *Registry) All() []CertRecord {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]CertRecord, 0, len(r.records))
	for _, rec := range r.records {
		out = append(out, *rec)
	}
	return out
}
