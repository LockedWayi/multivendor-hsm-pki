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

	// modernc.org/sqlite is pure Go. internal/pkcs11 carries the one cgo
	// dependency this repository accepts, and a build failure here must not
	// look like an HSM toolchain problem.
	_ "modernc.org/sqlite"
)

// schema is applied on every Open. Every statement is IF NOT EXISTS.
// Serial numbers and CRL numbers are TEXT holding a decimal big.Int: a
// 128-bit serial does not fit SQLite's 64-bit INTEGER.
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

// OpenSQLite opens the store at path, creating it if absent. logger may be
// nil. crlNumberFloor may be nil; when set, it is the lowest number a
// fresh store seeds its counter with, for a store rebuilt on a host whose
// clock has moved backwards. An existing counter is never touched.
func OpenSQLite(ctx context.Context, path string, logger *slog.Logger, crlNumberFloor *big.Int) (*SQLite, error) {
	// synchronous=full fsyncs on every commit; a commit lost to a power
	// failure would reissue a CRL number under different content.
	// _txlock=immediate takes the write lock when a transaction begins, so
	// two transactions cannot both read and then deadlock on the upgrade.
	db, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(full)&_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_txlock=immediate")
	if err != nil {
		return nil, fmt.Errorf("store: opening %s: %w", path, err)
	}

	// One connection. The store is single-writer, and serializing at the
	// pool removes SQLITE_BUSY as a failure mode.
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
	// A plain INSERT, so the PRIMARY KEY constraint rejects a duplicate. An
	// upsert here un-revoked certificates; see ErrDuplicateSerial.
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
// conflict. Matched on SQLite's own error text, because the driver's error
// type has changed across versions.
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

// Revoke implements Store. The read and the write happen in one
// transaction, so two concurrent revocations of one serial cannot both
// see "not yet revoked" and overwrite each other's timestamp and reason.
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
	// An already revoked certificate keeps its original RevokedAt and
	// reason. See Store.Revoke.
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

// NextCRLNumber implements Store. The counter is read, incremented and
// written in one transaction, so two concurrent CRL generations cannot get
// the same number. A store with no counter row is seeded from the wall
// clock; see seedCRLNumber. That path logs, because on any start but the
// first it means the store was lost and rebuilt.
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
			// A guess below the real value strands every future CRL.
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

// marshalName stores a subject as the DER of its RDNSequence. The RFC
// 2253 string form cannot represent every attribute faithfully.
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
