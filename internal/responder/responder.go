// Package responder answers "is this one certificate good, right now"
// for the certificates this CA issued: a delegated OCSP responder (RFC
// 6960), the signing core's third consumer after certificates and CRLs.
//
// Delegated: it signs with its own purpose-separated key under its own
// certificate, issued by the intermediate with the ocspSigning extended
// key usage and id-pkix-ocsp-nocheck. The intermediate's key never signs
// a status response, so a compromised responder key can lie about status
// and nothing else.
//
// nocheck means a relying party is told not to check the responder
// certificate's own revocation status, so a compromised responder key
// stays usable for that certificate's whole life. The lifetime is
// therefore short and renewal is automatic: the responder re-issues its
// own certificate on the internal path when half its life has passed,
// checks that certificate at the point of signing and not only at
// startup, and answers tryLater rather than signing under one that has
// expired.
//
// Answers come from the persistent store. A serial the store has never
// seen is unknown, never good: a responder that defaults to good is an
// oracle that vouches for forgeries.
package responder

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha1" // RFC 6960 CertID hashes; see issuerHashes.
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	"golang.org/x/crypto/ocsp"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/profile"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/store"
)

// clockSkewAllowance backdates thisUpdate and the point-of-use check,
// matching what the CA applies to a leaf's NotBefore and the CRL's
// thisUpdate.
const clockSkewAllowance = 5 * time.Minute

// Config is what New needs.
type Config struct {
	// Issuer is the intermediate: it issues the responder's certificate
	// and is the issuer every response is about.
	Issuer *ca.CA
	// Records is the store the responder answers from, and the one the
	// responder's own certificate is recorded in.
	Records store.Store
	// Signer signs responses with the responder key. On the service it
	// is the HSM-backed signer over the key under the configured label;
	// the key never leaves the token.
	Signer crypto.Signer
	// Profile is the ocsp-responder profile the responder's certificate
	// is issued under.
	Profile *profile.Profile
	// Subject is the responder certificate's common name.
	Subject string
	// Validity is how long a response is good for: nextUpdate is
	// thisUpdate plus this. The service uses the CRL's window, so the
	// two channels make the same freshness promise.
	Validity time.Duration
	Logger   *slog.Logger
}

// Responder is a delegated OCSP responder for one issuer.
type Responder struct {
	issuer  *ca.CA
	records store.Store
	signer  crypto.Signer
	profile *profile.Profile
	subject string
	window  time.Duration
	logger  *slog.Logger

	// The issuer's hashes, by algorithm, to recognise a request as one
	// this responder is authoritative for.
	nameHash map[crypto.Hash][]byte
	keyHash  map[crypto.Hash][]byte

	mu sync.Mutex
	// cert is the current responder certificate. Swapped by Renew.
	cert *x509.Certificate
	// cache holds signed responses for serials the store knows, until
	// their nextUpdate. Unknown serials are never cached, so the cache
	// is bounded by the store and not by a client's imagination.
	cache map[string]cached
}

type cached struct {
	der        []byte
	nextUpdate time.Time
}

// New builds a responder and issues its first certificate. It fails if
// the profile is not the internal-only one, if the certificate cannot be
// issued, or if the store will not record it.
func New(ctx context.Context, cfg Config) (*Responder, error) {
	if cfg.Issuer == nil || cfg.Records == nil || cfg.Signer == nil || cfg.Profile == nil {
		return nil, errors.New("responder: issuer, records, signer and profile are all required")
	}
	if !profile.InternalOnly(cfg.Profile.Name) {
		return nil, fmt.Errorf("responder: the responder certificate is issued under %q, not under %q", profile.InternalOnlyProfile, cfg.Profile.Name)
	}
	if cfg.Validity <= 0 {
		return nil, errors.New("responder: response validity must be positive")
	}
	if cfg.Subject == "" {
		cfg.Subject = cfg.Issuer.Certificate().Subject.CommonName + " OCSP Responder"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	r := &Responder{
		issuer: cfg.Issuer, records: cfg.Records, signer: cfg.Signer, profile: cfg.Profile,
		subject: cfg.Subject, window: cfg.Validity, logger: cfg.Logger,
		cache: make(map[string]cached),
	}
	var err error
	if r.nameHash, r.keyHash, err = issuerHashes(cfg.Issuer.Certificate()); err != nil {
		return nil, err
	}
	if err := r.Renew(ctx); err != nil {
		return nil, fmt.Errorf("responder: issuing the first responder certificate: %w", err)
	}
	return r, nil
}

// Certificate returns the responder certificate currently in use.
func (r *Responder) Certificate() *x509.Certificate {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.cert
}

// Renew issues a fresh responder certificate over the responder key,
// records it, and swaps it in. The request is signed by the responder
// key itself, the same proof of possession every other requester gives,
// so the certificate comes out of the path the API serves rather than a
// template of its own. The cache is dropped: responses signed under the
// old certificate stay valid until their nextUpdate, but a relying party
// that fetches the new one should not be handed the old.
func (r *Responder) Renew(ctx context.Context) error {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: r.subject},
	}, r.signer)
	if err != nil {
		return fmt.Errorf("creating the responder's request: %w", err)
	}
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return fmt.Errorf("parsing the responder's request: %w", err)
	}
	cert, err := r.issuer.Issue(csr, r.profile)
	if err != nil {
		return fmt.Errorf("issuing the responder certificate: %w", err)
	}
	// Recorded like every certificate this CA signs. nocheck means no
	// relying party will ask about it, but the record is what says it
	// exists.
	if err := r.records.Record(ctx, store.CertRecord{
		Serial: cert.SerialNumber, Subject: cert.Subject, NotAfter: cert.NotAfter, Status: store.StatusValid,
	}); err != nil {
		return fmt.Errorf("recording the responder certificate %s: %w", cert.SerialNumber, err)
	}
	r.mu.Lock()
	r.cert = cert
	r.cache = make(map[string]cached)
	r.mu.Unlock()
	r.logger.Info("OCSP responder certificate issued",
		"serial", cert.SerialNumber.String(), "not_after", cert.NotAfter)
	return nil
}

// RunRenewal renews the certificate once half its life has passed,
// checking every interval, until ctx ends. A failed renewal is logged and
// retried at the next interval; while the current certificate is still
// valid the responder keeps answering, and once it is not, Respond
// answers tryLater rather than signing under it.
func (r *Responder) RunRenewal(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !r.dueForRenewal(time.Now()) {
				continue
			}
			if err := r.Renew(ctx); err != nil {
				r.logger.Error("OCSP responder certificate renewal failed; the responder answers tryLater once the current certificate expires", "error", err)
			}
		}
	}
}

// dueForRenewal reports whether more than half the certificate's life is
// gone.
func (r *Responder) dueForRenewal(now time.Time) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cert == nil {
		return true
	}
	half := r.cert.NotBefore.Add(r.cert.NotAfter.Sub(r.cert.NotBefore) / 2)
	return now.After(half)
}

// Invalidate drops every cached response. Called on revocation, so the
// next request for that serial is answered from the store rather than
// from a response signed before the revocation.
func (r *Responder) Invalidate() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.cache = make(map[string]cached)
}

// Outcome says what Respond did, for the log and the HTTP layer. The
// DER is always a well-formed OCSPResponse, an error response included.
type Outcome struct {
	// Status is the certificate status for a successful response, or -1
	// for an error response.
	Status int
	// Error names the error response returned, or "" on success.
	Error string
	// NextUpdate is when a successful response stops being fresh.
	NextUpdate time.Time
	// Cached reports whether the response came from the cache.
	Cached bool
}

// Respond answers one DER-encoded OCSP request. It never returns an
// error: a malformed request, a request about another issuer, a store
// failure and an expired responder certificate each get the RFC 6960
// error response that says so, and the Outcome says which.
func (r *Responder) Respond(ctx context.Context, reqDER []byte) ([]byte, Outcome) {
	req, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return ocsp.MalformedRequestErrorResponse, Outcome{Status: -1, Error: "malformedRequest"}
	}
	if req.SerialNumber == nil || req.SerialNumber.Sign() <= 0 {
		return ocsp.MalformedRequestErrorResponse, Outcome{Status: -1, Error: "malformedRequest"}
	}
	nameHash, ok := r.nameHash[req.HashAlgorithm]
	if !ok {
		// A hash this responder does not compute the issuer under. The
		// request may be well-formed; it is one this responder cannot
		// answer.
		return ocsp.MalformedRequestErrorResponse, Outcome{Status: -1, Error: "malformedRequest"}
	}
	if !equal(nameHash, req.IssuerNameHash) || !equal(r.keyHash[req.HashAlgorithm], req.IssuerKeyHash) {
		// About some other issuer. RFC 6960 §2.3: unauthorized is the
		// response for a request the responder is not authoritative
		// for. Not unknown, which would be a statement about a serial
		// under this issuer.
		return ocsp.UnauthorizedErrorResponse, Outcome{Status: -1, Error: "unauthorized"}
	}

	now := time.Now()
	key := req.SerialNumber.String()

	r.mu.Lock()
	cert := r.cert
	if c, hit := r.cache[key]; hit && now.Before(c.nextUpdate) {
		r.mu.Unlock()
		status := ocsp.Good
		if parsed, err := ocsp.ParseResponse(c.der, nil); err == nil {
			status = parsed.Status
		}
		return c.der, Outcome{Status: status, NextUpdate: c.nextUpdate, Cached: true}
	}
	r.mu.Unlock()

	// The responder's own authority, at the point of use. A process
	// whose certificate was valid at startup is still running after it
	// expires, and a signature under an expired certificate is not an
	// answer.
	if cert == nil || now.Add(clockSkewAllowance).Before(cert.NotBefore) || now.After(cert.NotAfter) {
		r.logger.Error("OCSP responder certificate is outside its validity window; answering tryLater",
			"not_before", certTime(cert, true), "not_after", certTime(cert, false))
		return ocsp.TryLaterErrorResponse, Outcome{Status: -1, Error: "tryLater"}
	}

	rec, found, err := r.records.Get(ctx, req.SerialNumber)
	if err != nil {
		// The store is the only source of truth. Without it the honest
		// answer is "ask again", never good.
		r.logger.Error("OCSP store lookup failed; answering tryLater", "serial", key, "error", err)
		return ocsp.TryLaterErrorResponse, Outcome{Status: -1, Error: "tryLater"}
	}

	tmpl := ocsp.Response{
		SerialNumber: req.SerialNumber,
		ProducedAt:   now,
		ThisUpdate:   now.Add(-clockSkewAllowance),
		NextUpdate:   now.Add(r.window),
		IssuerHash:   req.HashAlgorithm,
		Certificate:  cert,
	}
	switch {
	case !found:
		tmpl.Status = ocsp.Unknown
	case rec.Status == store.StatusRevoked:
		tmpl.Status = ocsp.Revoked
		tmpl.RevokedAt = rec.RevokedAt
		tmpl.RevocationReason = int(rec.RevocationReason)
	default:
		tmpl.Status = ocsp.Good
	}

	der, err := ocsp.CreateResponse(r.issuer.Certificate(), cert, tmpl, r.signer)
	if err != nil {
		r.logger.Error("OCSP response signing failed; answering tryLater", "serial", key, "error", err)
		return ocsp.TryLaterErrorResponse, Outcome{Status: -1, Error: "tryLater"}
	}
	if found {
		r.mu.Lock()
		// Only if the certificate did not change underneath: a response
		// signed under a certificate Renew has just replaced is not
		// cached under the new one.
		if r.cert == cert {
			r.cache[key] = cached{der: der, nextUpdate: tmpl.NextUpdate}
		}
		r.mu.Unlock()
	}
	return der, Outcome{Status: tmpl.Status, NextUpdate: tmpl.NextUpdate}
}

func certTime(c *x509.Certificate, before bool) any {
	if c == nil {
		return nil
	}
	if before {
		return c.NotBefore
	}
	return c.NotAfter
}

func equal(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// issuerHashes computes the issuer name and key hashes a request
// identifies the issuer by (RFC 6960 §4.1.1), for SHA-1, which every
// client sends by default, and SHA-256. The key hash is over the
// subjectPublicKey BIT STRING's bytes, not the whole SubjectPublicKeyInfo.
func issuerHashes(issuer *x509.Certificate) (map[crypto.Hash][]byte, map[crypto.Hash][]byte, error) {
	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(issuer.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, nil, fmt.Errorf("responder: parsing the issuer's public key info: %w", err)
	}
	name := map[crypto.Hash][]byte{}
	key := map[crypto.Hash][]byte{}
	for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256} {
		var n, k []byte
		switch h {
		case crypto.SHA1:
			// RFC 6960 §4.1.1 identifies the issuer by hashes under the
			// hash the client chose, and every client sends SHA-1 by
			// default; a responder refusing it answers no request from
			// openssl ocsp or any TLS stack. A lookup key, not a
			// signature: the response is signed with ECDSA over SHA-256.
			// nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1
			s1 := sha1.Sum(issuer.RawSubject)
			// Same reason, the key hash half of the same CertID.
			// nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1
			s2 := sha1.Sum(spki.PublicKey.RightAlign())
			n, k = s1[:], s2[:]
		case crypto.SHA256:
			s1 := sha256.Sum256(issuer.RawSubject)
			s2 := sha256.Sum256(spki.PublicKey.RightAlign())
			n, k = s1[:], s2[:]
		}
		name[h], key[h] = n, k
	}
	return name, key, nil
}

// SerialOf is a small helper for callers and tests that need the serial
// a request is about without parsing it themselves.
func SerialOf(reqDER []byte) (*big.Int, error) {
	req, err := ocsp.ParseRequest(reqDER)
	if err != nil {
		return nil, err
	}
	return req.SerialNumber, nil
}
