// Package store holds the CA's issuance and revocation records, and the CRL
// number counter, behind one interface with two implementations.
//
// # Why this is its own package
//
// These records are CA domain state, not transport state. They lived in
// internal/api until Phase 3b because the HTTP layer was their only consumer,
// but that put a database concern inside the package whose job is parsing
// requests — and it is the reason internal/ca had to define its own
// RevokedCert rather than share a type, to avoid a domain package importing
// the HTTP layer built on top of it. Moving them here removes that
// inversion: api depends on store, ca stays free of both.
//
// # Why an interface
//
// Not speculative abstraction — there are two real implementations with
// different jobs. Memory is what tests run against, so the suite needs no
// filesystem and no driver. SQLite is what the service runs on, because a
// restart that erases revocations is a security regression, not a durability
// inconvenience: a certificate revoked for incident response would reappear
// as valid in the next CRL (docs/phases/phase-3b-pki-hardening.md).
//
// The interface is also what makes the eventual move to an external database
// a swap rather than a rewrite, if replicas ever exist. Until then the
// embedded store is single-writer by design.
package store

import (
	"context"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"time"
)

// ErrCertNotFound is returned by Revoke when no record exists for the given
// serial.
var ErrCertNotFound = errors.New("store: certificate not found")

// Status is a certificate's lifecycle state.
type Status string

const (
	StatusValid   Status = "valid"
	StatusRevoked Status = "revoked"
)

// CertRecord is what the store remembers about one issued certificate.
type CertRecord struct {
	Serial   *big.Int
	Subject  pkix.Name
	NotAfter time.Time
	Status   Status

	RevokedAt time.Time
	// RevocationReason is a CRLReason code (RFC 5280 §5.3.1), meaningful
	// only when Status is StatusRevoked.
	RevocationReason int
}

// Store records what the CA has issued and revoked, and hands out CRL
// numbers. Implementations must be safe for concurrent use.
type Store interface {
	// Record stores a newly issued certificate.
	Record(ctx context.Context, rec CertRecord) error

	// Get returns the record for serial. The boolean reports whether one
	// exists; a false with a nil error means "no such certificate", which is
	// an answer rather than a failure.
	Get(ctx context.Context, serial *big.Int) (CertRecord, bool, error)

	// Revoke marks the certificate with serial revoked.
	//
	// Re-revoking an already-revoked certificate is idempotent, not
	// rejected: it succeeds without changing the existing RevokedAt or
	// RevocationReason. Revocation is a one-way transition with no security
	// effect from being requested twice, and a retry — a client that timed
	// out waiting for the first response, an operator re-running a script —
	// should not fail because the first attempt actually succeeded.
	//
	// Returns ErrCertNotFound if no record exists for serial.
	Revoke(ctx context.Context, serial *big.Int, reason int, at time.Time) error

	// Revoked returns every revoked record, in no particular order. This is
	// what CRL generation consumes, and it is deliberately narrower than
	// "return everything and let the caller filter" — the store knows how to
	// answer this without materializing records the caller will discard.
	Revoked(ctx context.Context) ([]CertRecord, error)

	// NextCRLNumber returns a CRL number strictly greater than every number
	// this CA has issued before, and persists it before returning.
	//
	// RFC 5280 §5.2.3 requires CRL numbers to increase monotonically. A
	// verifier holding a higher-numbered CRL will ignore every later one it
	// receives, revocations included — so a counter that goes backwards does
	// not merely look untidy, it silently stops revocation from propagating.
	NextCRLNumber(ctx context.Context) (*big.Int, error)

	// Close releases whatever the implementation holds open.
	Close() error
}
