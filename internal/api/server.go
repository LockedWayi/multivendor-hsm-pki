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
	"net/http"
	"time"

	"github.com/LockedWayi/hsm-pki-platform/internal/ca"
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
)

// NewServer builds the HTTP handler for the CA service. issuer signs
// certificates; registry records what has been issued.
func NewServer(issuer *ca.CA, registry *Registry, logger *slog.Logger) http.Handler {
	s := &server{ca: issuer, registry: registry, logger: logger}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /certificates", s.handleIssueCertificate)

	return http.TimeoutHandler(mux, requestTimeout, `{"error":"request timed out"}`)
}

type server struct {
	ca       *ca.CA
	registry *Registry
	logger   *slog.Logger
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
			s.logger.Error("certificate issuance failed", "error", err)
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
