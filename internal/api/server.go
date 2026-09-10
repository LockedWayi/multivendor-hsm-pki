// Package api implements the CA's HTTP surface: certificate issuance,
// revocation, CRL distribution, and the health and readiness endpoints.
package api

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/LockedWayi/multivendor-hsm-pki/internal/ca"
	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
	"github.com/LockedWayi/multivendor-hsm-pki/internal/store"
)

const (
	// maxCSRBodyBytes bounds a POST /certificates request body. A PEM CSR
	// is a few hundred bytes to a few KB even with a large key or several
	// SANs; this is generous headroom, not a tight fit.
	maxCSRBodyBytes = 64 * 1024

	// requestTimeout bounds how long any single request may run. It is
	// enforced by http.TimeoutHandler. crypto.Signer has no context
	// parameter, so a Sign call in flight on the token is abandoned, not
	// interrupted.
	requestTimeout = 15 * time.Second

	// crlClockSkewAllowance backdates a CRL's thisUpdate, matching the
	// backdate Issue applies to a certificate's NotBefore.
	crlClockSkewAllowance = 5 * time.Minute
)

// Paths this service serves its public PKI artifacts at. They are exported
// because each is written into certificates as a CRL distribution point or
// an AIA pointer, and a certificate cannot be edited after signing.
// LeafDistributionFor composes the URLs from the same constants, so a
// route cannot be renamed without the certificates.
const (
	// CRLPath serves the CRL covering the leaves this intermediate issued.
	CRLPath = "/crl"
	// IntermediateCertPath serves this service's own intermediate
	// certificate: the AIA CA-Issuers target of every leaf it signs.
	IntermediateCertPath = "/intermediate.crt"
	// RootCertPath serves the ceremony-produced root certificate: the AIA
	// CA-Issuers target named in the intermediate certificate.
	RootCertPath = "/root.crt"
	// RootCRLPath serves the ceremony-produced root CRL: the distribution
	// point named in the intermediate certificate.
	RootCRLPath = "/root.crl"
)

// LeafDistributionFor returns the CDP and AIA URLs a service reachable at
// baseURL writes into every leaf. It lives beside the routes so the two
// cannot drift. baseURL is the origin a relying party can resolve, which
// is not always what the process binds. A trailing slash is tolerated and
// a path prefix is kept.
func LeafDistributionFor(baseURL string) ca.LeafDistribution {
	base := strings.TrimRight(baseURL, "/")
	return ca.LeafDistribution{
		CRLURL:        base + CRLPath,
		IssuerCertURL: base + IntermediateCertPath,
	}
}

// Media types for the artifacts served at the URLs embedded in
// certificates. They are DER, not PEM: RFC 2585 §3 defines
// application/pkix-cert and application/pkix-crl as single DER objects,
// and a client following a CRL distribution point does not sniff the
// encoding. OpenSSL 3.x fails outright on a PEM body there. PEM stays the
// on-disk format the ceremony writes; the conversion happens once, at
// startup.
const (
	// ContentTypeCert is RFC 2585 §3's type for a single DER certificate.
	ContentTypeCert = "application/pkix-cert"
	// ContentTypeCRL is RFC 2585 §3's type for a single DER CRL.
	ContentTypeCRL = "application/pkix-crl"
)

// RootArtifacts are the ceremony's public root certificate and root CRL,
// republished so the CDP and AIA URLs in the intermediate certificate
// resolve. Neither is key material, and serving them gives this service
// no use of the root's key.
type RootArtifacts struct {
	// CertDER is the root certificate, served at the intermediate's AIA
	// CA-Issuers URL.
	CertDER []byte
	// CRLDER is the root's CRL, served at the intermediate's CRL
	// distribution point. It covers exactly one certificate: the
	// intermediate.
	CRLDER []byte
}

// NewServer builds the HTTP handler for the CA service. issuer is the
// intermediate CA. adapter and workspace back the /readyz probe. records
// is the durable store and the source of CRL numbers. crlValidity sets
// each CRL's window. root carries the static artifacts.
func NewServer(issuer *ca.CA, adapter pk11.VendorAdapter, workspace pk11.Workspace, records store.Store, crlValidity time.Duration, root RootArtifacts, logger *slog.Logger) http.Handler {
	s := &server{
		ca:          issuer,
		adapter:     adapter,
		workspace:   workspace,
		store:       records,
		crlValidity: crlValidity,
		root:        root,
	}
	// x509.Certificate.Raw is already the DER RFC 2585 wants at that URL.
	if issuer != nil && issuer.Certificate() != nil {
		s.intermediateDER = issuer.Certificate().Raw
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("POST /certificates", s.handleIssueCertificate)
	mux.HandleFunc("POST /certificates/{serial}/revoke", s.handleRevoke)
	mux.HandleFunc("GET "+CRLPath, s.handleCRL)
	// The AIA CA-Issuers target of every leaf.
	mux.HandleFunc("GET "+IntermediateCertPath, s.handleIntermediateCert)
	// Static ceremony artifacts at fixed paths, so the ceremony's
	// -root-crl-url and -root-cert-url can point at them before the
	// certificates are signed.
	mux.HandleFunc("GET "+RootCertPath, s.handleRootCert)
	mux.HandleFunc("GET "+RootCRLPath, s.handleRootCRL)

	return withRequestLogging(logger, http.TimeoutHandler(mux, requestTimeout, `{"error":"request timed out"}`))
}

type server struct {
	ca          *ca.CA
	adapter     pk11.VendorAdapter
	workspace   pk11.Workspace
	store       store.Store
	crlValidity time.Duration
	root        RootArtifacts
	// intermediateDER is this service's own CA certificate, served at
	// GET /intermediate.crt.
	intermediateDER []byte

	crlMu            sync.Mutex
	cachedCRL        []byte
	cachedNextUpdate time.Time
}

// handleIntermediateCert serves this service's own intermediate
// certificate at the AIA CA-Issuers URL every leaf points at. A CA-Issuers
// URL that returns 404 is worse than none.
func (s *server) handleIntermediateCert(w http.ResponseWriter, r *http.Request) {
	s.serveDERArtifact(w, r, s.intermediateDER, ContentTypeCert, "intermediate certificate")
}

// handleRootCert serves the ceremony-produced root certificate at the AIA
// CA-Issuers URL the intermediate points at.
func (s *server) handleRootCert(w http.ResponseWriter, r *http.Request) {
	s.serveDERArtifact(w, r, s.root.CertDER, ContentTypeCert, "root certificate")
}

// handleRootCRL serves the ceremony-produced root CRL, verbatim. Producing
// it needs the root's key, which is offline. Refreshing it means running a
// ceremony.
func (s *server) handleRootCRL(w http.ResponseWriter, r *http.Request) {
	s.serveDERArtifact(w, r, s.root.CRLDER, ContentTypeCRL, "root CRL")
}

// serveDERArtifact writes one static DER artifact, or a 503 when it is
// absent. NewServer cannot reject a zero-valued RootArtifacts, and an
// empty 200 at a CRL distribution point would read to a relying party as
// a malformed CRL, which most treat as revocation unavailable.
func (s *server) serveDERArtifact(w http.ResponseWriter, r *http.Request, der []byte, contentType, what string) {
	if len(der) == 0 {
		loggerFromContext(r.Context()).Error("artifact is not available", "artifact", what)
		s.writeError(w, http.StatusServiceUnavailable, what+" is not available on this server")
		return
	}
	w.Header().Set("Content-Type", contentType)
	// These change only when a ceremony runs. An hour is short enough for a
	// re-ceremony to propagate and long enough for a CDN to stop
	// re-fetching.
	w.Header().Set("Cache-Control", "public, max-age=3600, must-revalidate")
	_, _ = w.Write(der)
}

type errorResponse struct {
	Error string `json:"error"`
}

func (s *server) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: msg})
}

// handleIssueCertificate implements POST /certificates: accept a PEM or
// DER CSR, validate it, and return the signed certificate. Every rejection
// responds before the result is recorded.
func (s *server) handleIssueCertificate(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxCSRBodyBytes)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		var tooLarge *http.MaxBytesError
		if errors.As(err, &tooLarge) {
			s.writeError(w, http.StatusRequestEntityTooLarge, "request body exceeds size limit")
			return
		}
		s.writeError(w, http.StatusBadRequest, "reading request body")
		return
	}

	csr, err := parseCSR(body)
	if err != nil {
		s.writeError(w, http.StatusBadRequest, "malformed CSR: "+err.Error())
		return
	}

	cert, err := s.ca.Issue(csr)
	if err != nil {
		status, msg := issueErrorResponse(err)
		if status >= 500 {
			// Internal detail stays in the log, not the response.
			loggerFromContext(r.Context()).Error("certificate issuance failed", "error", err)
		}
		s.writeError(w, status, msg)
		return
	}

	// The record is written before the certificate is returned, and a
	// failed write fails the request. A certificate whose issuance was
	// never recorded cannot be revoked later.
	if err := s.store.Record(r.Context(), store.CertRecord{
		Serial:   cert.SerialNumber,
		Subject:  cert.Subject,
		NotAfter: cert.NotAfter,
		Status:   store.StatusValid,
	}); err != nil {
		// Serials come from this CA's own crypto/rand, so a duplicate is a
		// defect, not a caller error. The store holds a different record
		// under that serial, and revoking it later would be ambiguous.
		loggerFromContext(r.Context()).Error("recording an issued certificate failed", "error", err, "serial", cert.SerialNumber.String())
		s.writeError(w, http.StatusInternalServerError, "certificate issuance failed")
		return
	}

	// The full chain, leaf first, then the intermediate, the order TLS uses
	// (RFC 8446 §4.4.2). The root is not included: it is the trust anchor
	// and is distributed out of band.
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusCreated)
	_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: s.ca.Certificate().Raw})
}

// parseCSR accepts a PEM CSR ("CERTIFICATE REQUEST" or the older "NEW
// CERTIFICATE REQUEST") or raw DER.
func parseCSR(body []byte) (*x509.CertificateRequest, error) {
	data := body
	if block, _ := pem.Decode(body); block != nil {
		if block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST" {
			return nil, errors.New("unexpected PEM block type " + block.Type)
		}
		data = block.Bytes
	}
	return x509.ParseCertificateRequest(data)
}

// revokeRequest is the optional JSON body for POST /certificates/{serial}/revoke.
// An empty or absent body revokes with CRLReason 0 (unspecified).
type revokeRequest struct {
	Reason int `json:"reason"`
}

// handleRevoke implements POST /certificates/{serial}/revoke. serial is
// decimal, as big.Int.String() writes it. An unknown serial is a 404.
// Revoking an already revoked certificate succeeds; see Store.Revoke.
func (s *server) handleRevoke(w http.ResponseWriter, r *http.Request) {
	serialStr := r.PathValue("serial")
	serial, ok := new(big.Int).SetString(serialStr, 10)
	if !ok {
		s.writeError(w, http.StatusBadRequest, "serial must be a decimal integer")
		return
	}

	var req revokeRequest
	if r.ContentLength != 0 {
		body, err := io.ReadAll(io.LimitReader(r.Body, 4096))
		if err != nil {
			s.writeError(w, http.StatusBadRequest, "reading request body")
			return
		}
		if len(body) > 0 {
			if err := json.Unmarshal(body, &req); err != nil {
				s.writeError(w, http.StatusBadRequest, "malformed request body")
				return
			}
		}
	}

	if err := s.store.Revoke(r.Context(), serial, store.RevocationReason(req.Reason), time.Now()); err != nil {
		if errors.Is(err, store.ErrCertNotFound) {
			s.writeError(w, http.StatusNotFound, "certificate not found")
			return
		}
		// A reason code outside RFC 5280 §5.3.1 is the caller's error.
		if errors.Is(err, store.ErrInvalidRevocationReason) {
			s.writeError(w, http.StatusBadRequest, "revocation reason is not a valid RFC 5280 CRLReason")
			return
		}
		loggerFromContext(r.Context()).Error("revocation failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "revocation failed")
		return
	}
	s.invalidateCRLCache()

	w.WriteHeader(http.StatusNoContent)
}

// invalidateCRLCache drops the cached CRL, so the next GET /crl includes
// this revocation at once rather than at nextUpdate.
func (s *server) invalidateCRLCache() {
	s.crlMu.Lock()
	defer s.crlMu.Unlock()
	s.cachedCRL = nil
}

// handleCRL implements GET /crl: serve the current CRL, regenerating it
// when the cached one is missing or past its nextUpdate.
func (s *server) handleCRL(w http.ResponseWriter, r *http.Request) {
	der, err := s.currentCRL(r.Context())
	if err != nil {
		loggerFromContext(r.Context()).Error("CRL generation failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "CRL generation failed")
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	// The cache lifetime is bound to the CRL's own nextUpdate, so a CDN
	// cannot serve it past the point this CA said it stops being
	// authoritative. must-revalidate forbids serving the stale copy when
	// the origin is unreachable.
	maxAge := int(time.Until(s.crlNextUpdate()).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}
	w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, must-revalidate", maxAge))
	_, _ = w.Write(der)
}

// crlNextUpdate reports the cached CRL's nextUpdate, for the cache header.
func (s *server) crlNextUpdate() time.Time {
	s.crlMu.Lock()
	defer s.crlMu.Unlock()
	return s.cachedNextUpdate
}

// currentCRL returns the cached CRL, regenerating it when the cache is
// empty or past its nextUpdate.
//
// The lock is held across generation on purpose. That makes it
// single-flight: ten concurrent requests on a cold cache produce one token
// signature and nine waiters. Releasing the lock to let readers through
// would turn a cache miss into many signatures at the token. Keep the
// single-flight property if this ever changes.
func (s *server) currentCRL(ctx context.Context) ([]byte, error) {
	s.crlMu.Lock()
	defer s.crlMu.Unlock()

	now := time.Now()
	if s.cachedCRL != nil && now.Before(s.cachedNextUpdate) {
		return s.cachedCRL, nil
	}

	records, err := s.store.Revoked(ctx)
	if err != nil {
		return nil, err
	}
	revoked := make([]ca.RevokedCert, 0, len(records))
	for _, rec := range records {
		revoked = append(revoked, ca.RevokedCert{
			Serial:     rec.Serial,
			RevokedAt:  rec.RevokedAt,
			ReasonCode: int(rec.RevocationReason),
		})
	}

	// The CRL number comes from the store, which persists it before
	// returning.
	number, err := s.store.NextCRLNumber(ctx)
	if err != nil {
		return nil, err
	}

	// thisUpdate is backdated for clock skew, as Issue backdates NotBefore.
	thisUpdate := now.Add(-crlClockSkewAllowance)
	nextUpdate := now.Add(s.crlValidity)
	// A CRL may not claim to be authoritative past the issuer's NotAfter.
	// Clamped, not refused: a shorter CRL is valid and asks the verifier to
	// come back sooner, and refusing would remove the CA's ability to
	// publish revocations in the window where re-issuance is most likely.
	if issuerNotAfter := s.ca.Certificate().NotAfter; nextUpdate.After(issuerNotAfter) {
		nextUpdate = issuerNotAfter
	}

	der, err := s.ca.BuildCRL(revoked, thisUpdate, nextUpdate, number)
	if err != nil {
		return nil, err
	}
	s.cachedCRL = der
	s.cachedNextUpdate = nextUpdate
	return der, nil
}

// issueErrorResponse maps a ca.Issue error to an HTTP status and a message
// safe to return. The listed reasons are about the caller's CSR and map to
// 400. ca.ErrNoDistributionPoints is not listed: it is about this server's
// configuration, so it maps to 500.
func issueErrorResponse(err error) (int, string) {
	switch {
	case errors.Is(err, ca.ErrInvalidCSRSignature):
		return http.StatusBadRequest, "CSR signature is invalid"
	case errors.Is(err, ca.ErrEmptySubject):
		return http.StatusBadRequest, "CSR subject is empty"
	case errors.Is(err, ca.ErrDisallowedKeyType):
		return http.StatusBadRequest, "CSR public key type is not allowed"
	default:
		return http.StatusInternalServerError, "certificate issuance failed"
	}
}
