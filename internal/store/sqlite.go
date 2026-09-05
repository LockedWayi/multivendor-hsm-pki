package store

import (
	"context"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/asn1"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	// modernc.org/sqlite is a pure-Go SQLite. It is chosen over mattn's cgo
	// binding so this package adds no new cgo surface: internal/pkcs11
	// already carries the one cgo dependency this repository accepts, and
	// keeping the storage layer pure Go means a build failure there can
	// never be confused with an HSM toolchain problem.
	_ "modernc.org/sqlite"
)

// schema is applied on every Open. Every statement is IF NOT EXISTS, so
// opening an existing store is a no-op rather than a migration.
//
// Serial numbers and CRL numbers are TEXT holding a decimal big.Int, not
// INTEGER. A certificate serial is 128 bits of crypto/rand (ca.GenerateSerial)
// and does not fit in SQLite's 64-bit INTEGER; storing it as text is lossless
// and matches how the HTTP layer already addresses a certificate.
const schema = `
CREATE TABLE IF NOT EXISTS certificates (
    serial      TEXT PRIMARY KEY,
    subject_der BLOB NOT NULL,
    not_after   INTEGER NOT NULL,
    status      TEXT NOT NULL,
    revoked_at  INTEGER,
    reason      INTEGER
);
CREATE INDEX IF NOT EXISTS idx_certificates_status ON certificates(status);

CREATE TABLE IF NOT EXISTS crl_counter (
    id     INTEGER PRIMARY KEY CHECK (id = 1),
    number TEXT NOT NULL
);
`

// SQLite is the durable Store the service runs on.
type SQLite struct {
	db     *sql.DB
	logger *slog.Logger
	// crlNumberFloor raises the value a fresh store is seeded with. See
	// OpenSQLite.
	crlNumberFloor *big.Int
}

// OpenSQLite opens (creating if absent) the store at path.
//
// logger may be nil, in which case nothing is logged; it exists for one
// message that must not be silent — see NextCRLNumber's seeding path.
//
// crlNumberFloor may be nil. When set, it is the lowest number a *fresh*
// store will seed its CRL counter with; an existing counter is never
// touched. It is the operator's escape hatch for the one case the clock
// seed cannot cover on its own: a store that was lost and is being rebuilt
// on a host whose clock has since moved backwards, where the clock-derived
// seed could land below numbers verifiers already hold. Nobody can recover
// that number automatically — the thing that remembered it is what was
// lost — so an operator who does know it supplies it here.
func OpenSQLite(ctx context.Context, path string, logger *slog.Logger, crlNumberFloor *big.Int) (*SQLite, error) {
	// Three pragmas, each load-bearing.
	//
	// synchronous=full fsyncs on every commit. It is SQLite's default today,
	// which is exactly why it is set explicitly: WAL mode is very commonly
	// paired with synchronous=normal for throughput, and someone doing that
	// here would trade away the durability the CRL counter depends on. A
	// commit lost to a power failure means reissuing a CRL number that has
	// already been served under different content — an RFC 5280 §5.2.3
	// violation produced by a performance tweak.
	//
	// _txlock=immediate takes the write lock when a transaction begins
	// rather than on its first write. Without it, two transactions can both
	// begin, both read, and then deadlock when the second tries to upgrade —
	// SQLITE_BUSY on a path that has no way to retry safely.
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(full)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("store: opening %s: %w", path, err)
	}

	// One connection, deliberately. The embedded store is single-writer by
	// design at this scale, and serializing at the
	// pool removes SQLITE_BUSY as a failure mode entirely rather than
	// managing it with retries. If replicas ever exist this moves to an
	// external database, which is the swap the Store interface exists to
	// permit — it is not fixed by allowing more connections here.
	db.SetMaxOpenConns(1)

	if _, err := db.ExecContext(ctx, schema); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("store: applying schema to %s: %w", path, err)
	}
	return &SQLite{db: db, logger: logger, crlNumberFloor: crlNumberFloor}, nil
}

// Record implements Store.
func (s *SQLite) Record(ctx context.Context, rec CertRecord) error {
	subjectDER, err := marshalName(rec.Subject)
	if err != nil {
		return err
	}
	// A plain INSERT, so the PRIMARY KEY constraint rejects a duplicate.
	//
	// This used to be an upsert, which was a quiet security defect: the
	// incoming record carries StatusValid, so re-recording an
	// already-revoked serial silently un-revoked it and dropped it out of
	// the CRL. See ErrDuplicateSerial.
	_, err = s.db.ExecContext(ctx, `
        INSERT INTO certificates (serial, subject_der, not_after, status, revoked_at, reason)
        VALUES (?, ?, ?, ?, NULL, NULL)`,
		rec.Serial.String(), subjectDER, NormalizeTime(rec.NotAfter).Unix(), string(rec.Status))
	if err != nil {
		if isUniqueConstraintViolation(err) {
			return fmt.Errorf("%w: %s", ErrDuplicateSerial, rec.Serial)
		}
		return fmt.Errorf("store: recording certificate %s: %w", rec.Serial, err)
	}
	return nil
}

// isUniqueConstraintViolation reports whether err is SQLite's primary-key
// conflict.
//
// Matched on the driver's message rather than a typed error: modernc's
// driver returns its error as a formatted string, and depending on its
// internal type here would couple this package to an implementation detail
// that has changed across its versions. The substring it looks for is part
// of SQLite's own stable error text, not the driver's wrapping.
func isUniqueConstraintViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}

// Get implements Store.
func (s *SQLite) Get(ctx context.Context, serial *big.Int) (CertRecord, bool, error) {
	row := s.db.QueryRowContext(ctx, `
        SELECT serial, subject_der, not_after, status, revoked_at, reason
        FROM certificates WHERE serial = ?`, serial.String())

	rec, err := scanRecord(row)
	if errors.Is(err, sql.ErrNoRows) {
		return CertRecord{}, false, nil
	}
	if err != nil {
		return CertRecord{}, false, fmt.Errorf("store: reading certificate %s: %w", serial, err)
	}
	return rec, true, nil
}

// Revoke implements Store.
//
// The read and the write happen in one transaction. Without it, two
// concurrent revocations of the same serial could both observe "not yet
// revoked" and the second would overwrite the first's timestamp and reason —
// quietly rewriting when and why a certificate was revoked, which is exactly
// the record an incident review depends on.
func (s *SQLite) Revoke(ctx context.Context, serial *big.Int, reason RevocationReason, at time.Time) error {
	if !reason.Valid() {
		return fmt.Errorf("%w: %d", ErrInvalidRevocationReason, reason)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("store: beginning revoke transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var status string
	err = tx.QueryRowContext(ctx, `SELECT status FROM certificates WHERE serial = ?`, serial.String()).Scan(&status)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrCertNotFound
	}
	if err != nil {
		return fmt.Errorf("store: reading certificate %s for revocation: %w", serial, err)
	}
	// Idempotent by contract: an already-revoked certificate keeps its
	// original RevokedAt and reason. See Store.Revoke.
	if Status(status) == StatusRevoked {
		return tx.Commit()
	}

	if _, err := tx.ExecContext(ctx, `
        UPDATE certificates SET status = ?, revoked_at = ?, reason = ? WHERE serial = ?`,
		string(StatusRevoked), NormalizeTime(at).Unix(), int(reason), serial.String()); err != nil {
		return fmt.Errorf("store: revoking certificate %s: %w", serial, err)
	}
	return tx.Commit()
}

// Revoked implements Store.
func (s *SQLite) Revoked(ctx context.Context) ([]CertRecord, error) {
	rows, err := s.db.QueryContext(ctx, `
        SELECT serial, subject_der, not_after, status, revoked_at, reason
        FROM certificates WHERE status = ?`, string(StatusRevoked))
	if err != nil {
		return nil, fmt.Errorf("store: listing revoked certificates: %w", err)
	}
	defer rows.Close()

	var out []CertRecord
	for rows.Next() {
		rec, err := scanRecord(rows)
		if err != nil {
			return nil, fmt.Errorf("store: reading a revoked certificate: %w", err)
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("store: iterating revoked certificates: %w", err)
	}
	return out, nil
}

// NextCRLNumber implements Store.
//
// The counter is read, incremented, and written inside one transaction, so
// two concurrent CRL generations cannot be handed the same number. A repeated
// number is not cosmetic: RFC 5280 §5.2.3 lets a verifier keep the
// higher-numbered CRL it already holds and ignore later ones, so a collision
// can strand revocations indefinitely.
//
// A store with no counter row is seeded from the wall clock rather than from
// 1 — see seedCRLNumber for why, and note that this is the only path that
// logs: an empty counter means either a first start or a store that was lost
// and rebuilt, and the second is worth noticing in an operator's logs rather
// than absorbing silently.
func (s *SQLite) NextCRLNumber(ctx context.Context) (*big.Int, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("store: beginning CRL number transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var stored string
	err = tx.QueryRowContext(ctx, `SELECT number FROM crl_counter WHERE id = 1`).Scan(&stored)

	var next *big.Int
	switch {
	case errors.Is(err, sql.ErrNoRows):
		next = seedCRLNumber(time.Now())
		if s.crlNumberFloor != nil && s.crlNumberFloor.Cmp(next) > 0 {
			next = new(big.Int).Set(s.crlNumberFloor)
		}
		if s.logger != nil {
			s.logger.Warn("CRL counter is empty; seeding it from the wall clock. This is expected on a first start, and means the store was lost and rebuilt on any later one.",
				"seeded_crl_number", next.String())
		}
	case err != nil:
		return nil, fmt.Errorf("store: reading CRL counter: %w", err)
	default:
		current, ok := new(big.Int).SetString(stored, 10)
		if !ok {
			// A counter we cannot parse is worse than one we do not have:
			// continuing would mean guessing, and a guess below the real
			// value strands every future CRL. Reject rather than repair
			//
			return nil, fmt.Errorf("store: CRL counter %q is not a valid integer; refusing to guess the next number", stored)
		}
		next = new(big.Int).Add(current, big.NewInt(1))
	}

	if _, err := tx.ExecContext(ctx, `
        INSERT INTO crl_counter (id, number) VALUES (1, ?)
        ON CONFLICT(id) DO UPDATE SET number = excluded.number`, next.String()); err != nil {
		return nil, fmt.Errorf("store: persisting CRL counter: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("store: committing CRL counter: %w", err)
	}
	return next, nil
}

// Close implements Store.
func (s *SQLite) Close() error { return s.db.Close() }

// rowScanner is satisfied by both *sql.Row and *sql.Rows, so one scan
// routine serves Get and Revoked.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanRecord(sc rowScanner) (CertRecord, error) {
	var (
		serialStr  string
		subjectDER []byte
		notAfter   int64
		status     string
		revokedAt  sql.NullInt64
		reason     sql.NullInt64
	)
	if err := sc.Scan(&serialStr, &subjectDER, &notAfter, &status, &revokedAt, &reason); err != nil {
		return CertRecord{}, err
	}

	serial, ok := new(big.Int).SetString(serialStr, 10)
	if !ok {
		return CertRecord{}, fmt.Errorf("stored serial %q is not a valid integer", serialStr)
	}
	subject, err := unmarshalName(subjectDER)
	if err != nil {
		return CertRecord{}, err
	}

	rec := CertRecord{
		Serial:   serial,
		Subject:  subject,
		NotAfter: time.Unix(notAfter, 0).UTC(),
		Status:   Status(status),
	}
	if revokedAt.Valid {
		rec.RevokedAt = time.Unix(revokedAt.Int64, 0).UTC()
	}
	if reason.Valid {
		rec.RevocationReason = RevocationReason(reason.Int64)
	}
	return rec, nil
}

// marshalName stores a subject as the DER of its RDNSequence.
//
// The alternative — storing name.String() — is lossy: the RFC 2253 string
// form cannot represent every attribute type and value faithfully, so a
// subject would not survive a round trip through the store unchanged. A
// record of what a CA issued should return what it issued.
func marshalName(name pkix.Name) ([]byte, error) {
	der, err := asn1.Marshal(name.ToRDNSequence())
	if err != nil {
		return nil, fmt.Errorf("store: encoding subject: %w", err)
	}
	return der, nil
}

func unmarshalName(der []byte) (pkix.Name, error) {
	var rdns pkix.RDNSequence
	if _, err := asn1.Unmarshal(der, &rdns); err != nil {
		return pkix.Name{}, fmt.Errorf("store: decoding stored subject: %w", err)
	}
	var name pkix.Name
	name.FillFromRDNSequence(&rdns)
	return name, nil
}
