// Package api implements the CA's HTTP surface: certificate issuance,
// revocation, CRL distribution, and health/readiness endpoints. Routes are
// added incrementally as the phase that owns them lands (see
// docs/phases/phase-2-ca-core.md).
package api

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"sync"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/ca"
	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

const (
	// maxCSRBodyBytes bounds a POST /certificates request body. A PEM CSR
	// is a few hundred bytes to a few KB even with a large key or several
	// SANs; this is generous headroom, not a tight fit.
	maxCSRBodyBytes = 64 * 1024

	// requestTimeout bounds how long any single request may run.
	//
	// This is enforced at the HTTP transport boundary via
	// http.TimeoutHandler, not by threading a context deadline into the
	// HSM call: crypto.Signer — the standard library interface Signer
	// implements (internal/ca) — has no context parameter, so a Sign call
	// already in flight on the HSM cannot be cancelled from here. What
	// this does guarantee is that a slow or stuck request stops holding
	// the client's connection open past the deadline; the underlying HSM
	// call is abandoned, not interrupted.
	requestTimeout = 15 * time.Second

	// crlClockSkewAllowance backdates a CRL's thisUpdate, matching the
	// backdate Issue applies to a certificate's NotBefore.
	crlClockSkewAllowance = 5 * time.Minute
)

// NewServer builds the HTTP handler for the CA service. issuer signs
// certificates and CRLs; adapter and workspace back the /readyz probe;
// registry records what has been issued and revoked; crlValidity sets each
// generated CRL's thisUpdate/nextUpdate window.
func NewServer(issuer *ca.CA, adapter pk11.VendorAdapter, workspace pk11.Workspace, registry *Registry, crlValidity time.Duration, logger *slog.Logger) http.Handler {
	s := &server{
		ca:          issuer,
		adapter:     adapter,
		workspace:   workspace,
		registry:    registry,
		crlValidity: crlValidity,
		crlNumber:   big.NewInt(0),
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("POST /certificates", s.handleIssueCertificate)
	mux.HandleFunc("POST /certificates/{serial}/revoke", s.handleRevoke)
	mux.HandleFunc("GET /crl", s.handleCRL)

	return withRequestLogging(logger, http.TimeoutHandler(mux, requestTimeout, `{"error":"request timed out"}`))
}

type server struct {
	ca          *ca.CA
	adapter     pk11.VendorAdapter
	workspace   pk11.Workspace
	registry    *Registry
	crlValidity time.Duration

	crlMu            sync.Mutex
	crlNumber        *big.Int
	cachedCRL        []byte
	cachedNextUpdate time.Time
}

type errorResponse struct {
	Error string `json:"error"`
}

func (s *server) writeError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(errorResponse{Error: msg})
}

// handleIssueCertificate implements POST /certificates: accept a PEM or DER
// CSR, validate it, and return the signed certificate. Any rejection —
// malformed body, unparseable CSR, a CSR internal/ca.CA.Issue itself
// rejects, an oversized body — responds before Issue is ever called or
// before its result is recorded, so a bad request is rejected outright,
// never partially processed (CLAUDE.md §3.4).
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
			// Internal detail stays in the log, not the response — a 500
			// tells the caller something went wrong on this end, not what
			// (CLAUDE.md §3.4: never leak internal detail to an untrusted
			// caller).
			loggerFromContext(r.Context()).Error("certificate issuance failed", "error", err)
		}
		s.writeError(w, status, msg)
		return
	}

	s.registry.Record(CertRecord{
		Serial:   cert.SerialNumber,
		Subject:  cert.Subject,
		NotAfter: cert.NotAfter,
		Status:   StatusValid,
	})

	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusCreated)
	_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
}

// parseCSR accepts either a PEM-encoded ("CERTIFICATE REQUEST" or the
// legacy "NEW CERTIFICATE REQUEST" label) or raw DER certificate signing
// request.
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

// handleRevoke implements POST /certificates/{serial}/revoke. serial is the
// certificate's serial number in decimal — the form big.Int.String()
// produces, matching how this service's own records key themselves — not
// hex. An unknown serial is a 404; re-revoking an already-revoked
// certificate succeeds without error (see Registry.Revoke's doc comment
// for why that is idempotent rather than rejected).
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

	if err := s.registry.Revoke(serial, req.Reason, time.Now()); err != nil {
		if errors.Is(err, ErrCertNotFound) {
			s.writeError(w, http.StatusNotFound, "certificate not found")
			return
		}
		loggerFromContext(r.Context()).Error("revocation failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "revocation failed")
		return
	}
	s.invalidateCRLCache()

	w.WriteHeader(http.StatusNoContent)
}

// invalidateCRLCache drops the cached CRL so the next GET /crl regenerates
// one that includes this revocation immediately, rather than waiting up to
// nextUpdate to become visible. Discovered by hand while smoke-testing a
// running server: a time-only cache (valid until nextUpdate, full stop)
// technically satisfies "never serve a stale CRL past nextUpdate," but a
// revocation is exactly the kind of event an operator expects to take
// effect right away — a compromised certificate should not stay
// CRL-invisible for up to a full validity window just because nothing had
// re-requested the CRL since the last revocation.
func (s *server) invalidateCRLCache() {
	s.crlMu.Lock()
	defer s.crlMu.Unlock()
	s.cachedCRL = nil
}

// handleCRL implements GET /crl: serve the current CRL, regenerating it if
// the cached one is missing or has passed its nextUpdate — never serving a
// stale CRL past its stated validity window.
func (s *server) handleCRL(w http.ResponseWriter, r *http.Request) {
	der, err := s.currentCRL()
	if err != nil {
		loggerFromContext(r.Context()).Error("CRL generation failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "CRL generation failed")
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	_, _ = w.Write(der)
}

func (s *server) currentCRL() ([]byte, error) {
	s.crlMu.Lock()
	defer s.crlMu.Unlock()

	now := time.Now()
	if s.cachedCRL != nil && now.Before(s.cachedNextUpdate) {
		return s.cachedCRL, nil
	}

	var revoked []ca.RevokedCert
	for _, rec := range s.registry.All() {
		if rec.Status == StatusRevoked {
			revoked = append(revoked, ca.RevokedCert{
				Serial:     rec.Serial,
				RevokedAt:  rec.RevokedAt,
				ReasonCode: rec.RevocationReason,
			})
		}
	}

	// Backdate thisUpdate the same few minutes Issue backdates NotBefore,
	// so a verifier whose clock trails this host's does not reject a CRL
	// that is technically not valid yet.
	thisUpdate := now.Add(-crlClockSkewAllowance)
	nextUpdate := now.Add(s.crlValidity)
	s.crlNumber = s.nextCRLNumber(now)

	der, err := s.ca.BuildCRL(revoked, thisUpdate, nextUpdate, s.crlNumber)
	if err != nil {
		return nil, err
	}
	s.cachedCRL = der
	s.cachedNextUpdate = nextUpdate
	return der, nil
}

// nextCRLNumber returns a CRL number strictly greater than any this
// service has issued — including across a restart.
//
// RFC 5280 §5.2.3 requires CRL numbers to increase monotonically, and a
// counter that starts from zero every time the process starts does not:
// after a restart the service would reissue number 1 while verifiers hold a
// previously distributed number 5, and a verifier keeping the higher-
// numbered CRL would then ignore every subsequent update, revocations
// included. Phase 2 has no persistent storage to read a counter back from
// (deliberately — see the phase file's out-of-scope list), so the wall
// clock supplies the monotonic component instead: Unix seconds only ever
// increase, survive a restart, and need nothing stored.
//
// max(previous+1, now) keeps it strictly increasing within a run too, for
// the case where two CRLs are generated inside the same second.
//
// The dependency this accepts is on the clock not moving backwards across a
// restart. A large backward step would repeat numbers already issued; NTP
// keeps that from happening in practice, and a persistent counter — the
// real fix — arrives with the storage layer that Phase 2 explicitly does
// not build.
func (s *server) nextCRLNumber(now time.Time) *big.Int {
	candidate := big.NewInt(now.UnixMilli())
	incremented := new(big.Int).Add(s.crlNumber, big.NewInt(1))
	if incremented.Cmp(candidate) > 0 {
		return incremented
	}
	return candidate
}

// issueErrorResponse maps a ca.Issue error to an HTTP status and a message
// safe to return to the caller. Every rejection reason ca.CA.Issue can
// return by name maps to 400 — it is a statement about the caller's own
// CSR, not internal server state; anything unrecognized maps to 500 with no
// detail exposed.
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
