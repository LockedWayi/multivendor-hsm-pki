// Package api implements the CA's HTTP surface: certificate issuance,
// revocation, CRL distribution, and health/readiness endpoints. Routes are
// added incrementally as the phase that owns them lands (see
// docs/phases/phase-2-ca-core.md).
package api

import (
	"context"
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
	"github.com/LockedWayi/hsm-pki-platform/internal/store"
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

// RootArtifacts are the ceremony-produced, public files the service
// republishes so that the CDP and AIA URLs baked into the intermediate
// certificate at ceremony time actually resolve.
//
// Neither field is key material, and serving them grants this service no
// ability whatsoever to use the root's key — that key exists only on a token
// this service never names (internal/config.CAConfig). What they do is make
// the chain verifiable by a relying party that holds neither: without the
// root CRL reachable, nothing can check whether the intermediate has been
// revoked, which is the one revocation signal the offline root exists to
// publish.
type RootArtifacts struct {
	// CertPEM is the root certificate, served at the intermediate's AIA
	// CA-Issuers URL.
	CertPEM []byte
	// CRLPEM is the root's CRL, served at the intermediate's CRL
	// distribution point. It covers exactly one certificate: the
	// intermediate.
	CRLPEM []byte
}

// NewServer builds the HTTP handler for the CA service. issuer is the
// intermediate CA: it signs leaf certificates and the leaf CRL, never
// anything root-tier. adapter and workspace back the /readyz probe;
// records is the durable store of what has been issued and revoked, and
// the source of CRL numbers; crlValidity sets each
// generated CRL's thisUpdate/nextUpdate window; root carries the static
// artifacts described on RootArtifacts.
func NewServer(issuer *ca.CA, adapter pk11.VendorAdapter, workspace pk11.Workspace, records store.Store, crlValidity time.Duration, root RootArtifacts, logger *slog.Logger) http.Handler {
	s := &server{
		ca:          issuer,
		adapter:     adapter,
		workspace:   workspace,
		store:       records,
		crlValidity: crlValidity,
		root:        root,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("POST /certificates", s.handleIssueCertificate)
	mux.HandleFunc("POST /certificates/{serial}/revoke", s.handleRevoke)
	mux.HandleFunc("GET /crl", s.handleCRL)
	// Static, ceremony-produced artifacts. The paths are fixed and
	// documented so an operator can point the ceremony's -root-crl-url and
	// -root-cert-url at them before the certificates that embed those URLs
	// are ever signed.
	mux.HandleFunc("GET /root.crt", s.handleRootCert)
	mux.HandleFunc("GET /root.crl", s.handleRootCRL)

	return withRequestLogging(logger, http.TimeoutHandler(mux, requestTimeout, `{"error":"request timed out"}`))
}

type server struct {
	ca          *ca.CA
	adapter     pk11.VendorAdapter
	workspace   pk11.Workspace
	store       store.Store
	crlValidity time.Duration
	root        RootArtifacts

	crlMu            sync.Mutex
	cachedCRL        []byte
	cachedNextUpdate time.Time
}

// handleRootCert serves the ceremony-produced root certificate at the AIA
// CA-Issuers URL the intermediate points at.
func (s *server) handleRootCert(w http.ResponseWriter, r *http.Request) {
	s.serveRootArtifact(w, r, s.root.CertPEM, "root certificate")
}

// handleRootCRL serves the ceremony-produced root CRL at the distribution
// point the intermediate points at.
//
// It is served verbatim rather than regenerated: producing it requires the
// root's key, which is offline and unreachable from here by design. Its
// validity window is set at ceremony time and is deliberately long, so
// refreshing it means re-running the ceremony (docs/phases/
// phase-3b-pki-hardening.md, "How the root CRL is produced").
func (s *server) handleRootCRL(w http.ResponseWriter, r *http.Request) {
	s.serveRootArtifact(w, r, s.root.CRLPEM, "root CRL")
}

// serveRootArtifact writes one static ceremony artifact, or fails honestly
// if it is absent.
//
// The absent case matters more than it looks. cmd/hsm-pki-server validates
// both artifacts at startup, but NewServer takes them by value and cannot
// reject a zero-valued RootArtifacts, so an in-process caller can construct
// a server without them. Writing an empty 200 there would be the worst
// outcome available: a relying party fetching the CRL distribution point
// would receive a successful response containing a malformed CRL, and the
// most likely way it handles that is to treat revocation as unavailable and
// carry on. A 503 says the artifact is missing, which is the truth
// (CLAUDE.md §3.4).
func (s *server) serveRootArtifact(w http.ResponseWriter, r *http.Request, pemBytes []byte, what string) {
	if len(pemBytes) == 0 {
		loggerFromContext(r.Context()).Error("root artifact is not configured", "artifact", what)
		s.writeError(w, http.StatusServiceUnavailable, what+" is not configured on this server")
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	_, _ = w.Write(pemBytes)
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

	// The record is written before the certificate is returned, and a
	// failure to write it fails the request. The alternative — hand back a
	// certificate whose issuance was never recorded — creates one this CA
	// cannot later revoke, because revocation is addressed by a serial the
	// store has never heard of. Better to fail an issuance than to issue
	// something unrevocable (CLAUDE.md §3.4).
	if err := s.store.Record(r.Context(), store.CertRecord{
		Serial:   cert.SerialNumber,
		Subject:  cert.Subject,
		NotAfter: cert.NotAfter,
		Status:   store.StatusValid,
	}); err != nil {
		loggerFromContext(r.Context()).Error("recording an issued certificate failed", "error", err, "serial", cert.SerialNumber.String())
		s.writeError(w, http.StatusInternalServerError, "certificate issuance failed")
		return
	}

	// Return the full chain, leaf first, then the issuing intermediate.
	//
	// A relying party validating this leaf needs the intermediate to build a
	// path to the root it trusts, and returning it here means it never has
	// to fetch it out of band. Leaf-first is the order TLS itself uses (RFC
	// 8446 §4.4.2) and what every tool that consumes a PEM bundle expects.
	//
	// The root is deliberately NOT included: it is the trust anchor, and a
	// relying party that would accept a root handed to it by the same server
	// that issued the certificate is not actually verifying anything. It is
	// distributed out of band, and /root.crt exists for path building, not
	// for establishing trust.
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusCreated)
	_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	_ = pem.Encode(w, &pem.Block{Type: "CERTIFICATE", Bytes: s.ca.Certificate().Raw})
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

	if err := s.store.Revoke(r.Context(), serial, req.Reason, time.Now()); err != nil {
		if errors.Is(err, store.ErrCertNotFound) {
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
	der, err := s.currentCRL(r.Context())
	if err != nil {
		loggerFromContext(r.Context()).Error("CRL generation failed", "error", err)
		s.writeError(w, http.StatusInternalServerError, "CRL generation failed")
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	_, _ = w.Write(der)
}

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
			ReasonCode: rec.RevocationReason,
		})
	}

	// The CRL number is taken from the store, which persists it before
	// returning. It used to be derived from the wall clock on every call
	// because Phase 2 had nowhere to keep a counter; the clock now only
	// seeds a store that has none, and every subsequent number is the
	// persisted one incremented (see store.Store.NextCRLNumber).
	number, err := s.store.NextCRLNumber(ctx)
	if err != nil {
		return nil, err
	}

	// Backdate thisUpdate the same few minutes Issue backdates NotBefore,
	// so a verifier whose clock trails this host's does not reject a CRL
	// that is technically not valid yet.
	thisUpdate := now.Add(-crlClockSkewAllowance)
	nextUpdate := now.Add(s.crlValidity)

	der, err := s.ca.BuildCRL(revoked, thisUpdate, nextUpdate, number)
	if err != nil {
		return nil, err
	}
	s.cachedCRL = der
	s.cachedNextUpdate = nextUpdate
	return der, nil
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
