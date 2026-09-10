package ca

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"
)

// RevokedCert is what a CRL entry needs. It is defined here so this package
// never imports the HTTP layer built on it.
type RevokedCert struct {
	Serial     *big.Int
	RevokedAt  time.Time
	ReasonCode int // CRLReason, RFC 5280 §5.3.1
}

// BuildCRL signs a CRL over revoked, valid from thisUpdate to nextUpdate,
// and returns its DER. number must be greater than every CRL number this
// CA issued before (RFC 5280 §5.2.3); the caller owns that counter.
func (c *CA) BuildCRL(revoked []RevokedCert, thisUpdate, nextUpdate time.Time, number *big.Int) ([]byte, error) {
	// An inverted or empty window would produce a CRL every verifier
	// rejects, far from the misconfiguration that caused it.
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
