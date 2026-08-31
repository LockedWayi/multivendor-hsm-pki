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

var (
	// ErrCertNotFound is returned by Revoke when no record exists for the
	// given serial.
	ErrCertNotFound = errors.New("store: certificate not found")

	// ErrDuplicateSerial is returned by Record when a record already exists
	// for that serial.
	//
	// Serial numbers are 128 bits of crypto/rand (ca.GenerateSerial), so a
	// genuine collision has probability around 2^-128. A duplicate therefore
	// is not a collision — it is a defect or a replay, and the one thing
	// that must not happen is to quietly overwrite the existing record. An
	// earlier version did exactly that, and because the incoming record
	// carries StatusValid it silently un-revoked any certificate that had
	// been revoked: the precise failure this package exists to prevent,
	// reached through a different door.
	ErrDuplicateSerial = errors.New("store: a certificate with this serial is already recorded")

	// ErrInvalidRevocationReason is returned by Revoke for a reason code
	// outside RFC 5280 §5.3.1.
	ErrInvalidRevocationReason = errors.New("store: revocation reason is not a valid CRLReason")
)

// RevocationReason is a CRLReason code (RFC 5280 §5.3.1).
//
// It is a named type rather than a bare int so that the valid set has one
// definition and one place to check it. Neither crypto/x509 nor this CA's
// CRL builder validates the code, so an unchecked int reaches the CRL
// verbatim — an API caller posting {"reason": 999} would otherwise produce
// a CRL entry no compliant verifier can interpret.
type RevocationReason int

// The CRLReason values RFC 5280 §5.3.1 assigns. Note the two gaps, both
// deliberate: 7 is unassigned, and 8 (removeFromCRL) is reserved for delta
// CRLs and is therefore not a reason a certificate can be revoked *with*.
const (
	ReasonUnspecified          RevocationReason = 0
	ReasonKeyCompromise        RevocationReason = 1
	ReasonCACompromise         RevocationReason = 2
	ReasonAffiliationChanged   RevocationReason = 3
	ReasonSuperseded           RevocationReason = 4
	ReasonCessationOfOperation RevocationReason = 5
	ReasonCertificateHold      RevocationReason = 6
	ReasonRemoveFromCRL        RevocationReason = 8
	ReasonPrivilegeWithdrawn   RevocationReason = 9
	ReasonAACompromise         RevocationReason = 10
)

// Valid reports whether r may be used to revoke a certificate on a base CRL.
//
// ReasonRemoveFromCRL is excluded even though RFC 5280 assigns it: it exists
// to withdraw an entry from a delta CRL, so revoking a certificate "because
// it should be removed from the CRL" is a contradiction. This CA issues base
// CRLs only.
func (r RevocationReason) Valid() bool {
	switch r {
	case ReasonUnspecified, ReasonKeyCompromise, ReasonCACompromise,
		ReasonAffiliationChanged, ReasonSuperseded, ReasonCessationOfOperation,
		ReasonCertificateHold, ReasonPrivilegeWithdrawn, ReasonAACompromise:
		return true
	default:
		return false
	}
}

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

	// RevokedAt is meaningful only when Status is StatusRevoked. It is
	// normalized to UTC at second granularity — see NormalizeTime.
	RevokedAt time.Time
	// RevocationReason is meaningful only when Status is StatusRevoked.
	RevocationReason RevocationReason
}

// NormalizeTime is the single definition of how this package stores an
// instant: UTC, truncated to the second.
//
// It exists because the two implementations disagreed without it. SQLite
// stores time.Time.Unix() and reads it back as UTC seconds, so it silently
// normalizes; Memory kept whatever it was handed, so a caller passing a
// local-zone time with nanoseconds got it back unchanged. Both then passed
// the shared conformance suite, because the suite happened to pass
// already-normalized values in — a divergence of exactly the kind two
// implementations behind one interface exist to catch, hidden by the test
// that should have caught it.
//
// Second granularity rather than nanosecond because that is what a CRL
// carries: RFC 5280 encodes revocation times as UTCTime or GeneralizedTime,
// neither of which has sub-second resolution. Storing more precision than
// the artifact can express would be precision the store cannot honor.
func NormalizeTime(t time.Time) time.Time {
	return t.UTC().Truncate(time.Second)
}

// Store records what the CA has issued and revoked, and hands out CRL
// numbers. Implementations must be safe for concurrent use.
type Store interface {
	// Record stores a newly issued certificate.
	//
	// Returns ErrDuplicateSerial if a record already exists for that serial.
	// It never overwrites one — see ErrDuplicateSerial for why silently
	// updating is the dangerous option.
	//
	// Timestamps on rec are normalized with NormalizeTime before storage, so
	// a value read back may differ from the one passed in.
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
	// Returns ErrCertNotFound if no record exists for serial, and
	// ErrInvalidRevocationReason if reason is not a CRLReason a base CRL may
	// carry. at is normalized with NormalizeTime.
	Revoke(ctx context.Context, serial *big.Int, reason RevocationReason, at time.Time) error

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
