package ca

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

// RevokedCert is the minimum a CRL entry needs. It is defined here, not as
// a reference to internal/api.CertRecord, so this package never imports
// the HTTP layer built on top of it (the engineering contract directory layering: ca is
// domain logic, api is transport).
type RevokedCert struct {
	Serial     *big.Int
	RevokedAt  time.Time
	ReasonCode int // CRLReason, RFC 5280 §5.3.1
}

// BuildCRL signs a new Certificate Revocation List over revoked, valid from
// thisUpdate until nextUpdate, and returns its DER encoding. number must be
// strictly greater than every CRL number this CA has issued before it
// (RFC 5280 §5.2.3) — the caller owns that counter, since only it knows
// how many CRLs have been served.
func (c *CA) BuildCRL(revoked []RevokedCert, thisUpdate, nextUpdate time.Time, number *big.Int) ([]byte, error) {
	// Reject an inverted or empty validity window here rather than emitting
	// a CRL that is expired the moment it is signed. A caller that computes
	// nextUpdate from a misconfigured duration (a zero or negative
	// crl_validity_hours) would otherwise produce a technically well-formed
	// CRL that every verifier rejects, and the failure would surface far
	// from its cause.
	if !nextUpdate.After(thisUpdate) {
		return nil, fmt.Errorf("ca: CRL nextUpdate (%s) must be after thisUpdate (%s)",
			nextUpdate.Format(time.RFC3339), thisUpdate.Format(time.RFC3339))
	}
	if number == nil || number.Sign() <= 0 {
		return nil, fmt.Errorf("ca: CRL number must be a positive integer")
	}

	entries := make([]x509.RevocationListEntry, len(revoked))
	for i, r := range revoked {
		entries[i] = x509.RevocationListEntry{
			SerialNumber:   r.Serial,
			RevocationTime: r.RevokedAt,
			ReasonCode:     r.ReasonCode,
		}
	}

	template := &x509.RevocationList{
		Number:                    number,
		ThisUpdate:                thisUpdate,
		NextUpdate:                nextUpdate,
		RevokedCertificateEntries: entries,
	}
	der, err := x509.CreateRevocationList(rand.Reader, template, c.cert, c.signer)
	if err != nil {
		return nil, fmt.Errorf("ca: CreateRevocationList: %w", err)
	}
	return der, nil
}
