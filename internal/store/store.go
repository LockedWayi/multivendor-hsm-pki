// Package store holds the CA's issuance and revocation records and the
// CRL number counter, behind one interface with two implementations.
// Memory is what tests run against. SQLite is what the service runs on: a
// restart that erased revocations would make a revoked certificate valid
// again. The interface is what makes a move to an external database a
// swap. Until then the embedded store is single-writer.
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

	// ErrDuplicateSerial is returned by Record when a record exists for that
	// serial. Serials are 128 bits of crypto/rand, so a duplicate is a
	// defect or a replay, not a collision. An earlier version overwrote the
	// record, and because the incoming record carries StatusValid it
	// silently un-revoked the certificate.
	ErrDuplicateSerial = errors.New("store: a certificate with this serial is already recorded")

	// ErrInvalidRevocationReason is returned by Revoke for a reason code
	// outside RFC 5280 §5.3.1.
	ErrInvalidRevocationReason = errors.New("store: revocation reason is not a valid CRLReason")
)

// RevocationReason is a CRLReason code (RFC 5280 §5.3.1). Neither
// crypto/x509 nor BuildCRL validates it, so it is checked here.
type RevocationReason int

// The CRLReason values RFC 5280 §5.3.1 assigns. 7 is unassigned and 8
// (removeFromCRL) is for delta CRLs.
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

// Valid reports whether r may be used to revoke a certificate on a base
// CRL. ReasonRemoveFromCRL withdraws an entry from a delta CRL, and this
// CA issues base CRLs only.
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
	// normalized to UTC at second granularity. See NormalizeTime.
	RevokedAt time.Time
	// RevocationReason is meaningful only when Status is StatusRevoked.
	RevocationReason RevocationReason
}

// NormalizeTime is how this package stores an instant: UTC, truncated to
// the second. SQLite stores Unix seconds and Memory kept what it was
// handed, so the two disagreed until this existed. A CRL carries UTCTime
// or GeneralizedTime, neither with sub-second resolution.
func NormalizeTime(t time.Time) time.Time {
	return t.UTC().Truncate(time.Second)
}

// Store records what the CA has issued and revoked, and hands out CRL
// numbers. Implementations must be safe for concurrent use.
type Store interface {
	// Record stores a newly issued certificate. It returns
	// ErrDuplicateSerial when a record exists for that serial and never
	// overwrites one. Timestamps are normalized with NormalizeTime.
	Record(ctx context.Context, rec CertRecord) error

	// Get returns the record for serial. false with a nil error means no
	// such certificate.
	Get(ctx context.Context, serial *big.Int) (CertRecord, bool, error)

	// Revoke marks the certificate with serial revoked. Revoking an already
	// revoked certificate succeeds and keeps the original RevokedAt and
	// reason: a retried request must not fail because the first attempt
	// succeeded. It returns ErrCertNotFound for an unknown serial and
	// ErrInvalidRevocationReason for a reason a base CRL cannot carry.
	Revoke(ctx context.Context, serial *big.Int, reason RevocationReason, at time.Time) error

	// Revoked returns every revoked record, in no particular order. CRL
	// generation consumes it.
	Revoked(ctx context.Context) ([]CertRecord, error)

	// NextCRLNumber returns a CRL number greater than every number issued
	// before, and persists it before returning. RFC 5280 §5.2.3 requires
	// monotonic numbers: a verifier holding a higher-numbered CRL ignores
	// every later one, revocations included.
	NextCRLNumber(ctx context.Context) (*big.Int, error)

	// Close releases whatever the implementation holds open.
	Close() error
}
