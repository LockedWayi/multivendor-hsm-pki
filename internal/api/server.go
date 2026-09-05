// Package api implements the CA's HTTP surface: certificate issuance,
// revocation, CRL distribution, and health/readiness endpoints. Routes are
// added incrementally as the phase that owns them lands (see
// ).
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

// Paths this service serves its public PKI artifacts at.
//
// They are exported constants rather than string literals in the mux
// because they are not private routing detail: each one is baked into a
// certificate as a CRL distribution point or an AIA pointer, and a
// certificate cannot be edited after it is signed. Renaming a route here
// without re-issuing every certificate that names it turns a live
// distribution point into a 404, so the URLs and the routes are built from
// one source (see LeafDistributionFor, which composes them, and
// cmd/hsm-pki-keytool's -root-crl-url / -root-cert-url, which an operator
// points at the last two).
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
// baseURL should write into every leaf it issues.
//
// It lives here, next to the routes, so the two cannot drift: the URL in a
// certificate and the path in the mux are built from the same constant, and
// a route rename that forgets the certificates is a compile-time change to
// both at once. The composition root (cmd/hsm-pki-server) joins this to
// ca.LoadIntermediateParams; internal/ca stays unaware of the HTTP surface
// above it, which is why it takes complete URLs rather than a base and a
// set of paths it would have to know.
//
// baseURL is the externally reachable origin of this service — what a
// relying party can actually resolve, which is not necessarily what the
// process binds to (server.listen_addr is commonly 0.0.0.0 behind a load
// balancer). A trailing slash is tolerated; a path prefix is preserved, so
// "https://pki.example.com/ca" yields "https://pki.example.com/ca/crl".
func LeafDistributionFor(baseURL string) ca.LeafDistribution {
	base := strings.TrimRight(baseURL, "/")
	return ca.LeafDistribution{
		CRLURL:        base + CRLPath,
		IssuerCertURL: base + IntermediateCertPath,
	}
}

// MIME types and encodings for the artifacts served at the URLs embedded in
// certificates.
//
// These are DER, not PEM, and that is a correctness requirement rather than
// a preference. RFC 5280 §4.2.1.13 and §4.2.2.1 point a relying party at
// these URLs, and RFC 2585 §3 defines what it will find there:
// application/pkix-cert and application/pkix-crl, each a single DER object.
// A client following a CRL distribution point does not sniff the encoding —
// measured against OpenSSL 3.x, a PEM body at a CDP fails outright with
// "No supported data to decode. Input type: DER", which a verifier is most
// likely to treat as "revocation unavailable" and carry on.
//
// PEM remains the on-disk format for the ceremony's output files, because
// that is what an operator copies between hosts and what the ceremony
// writes. The conversion happens once, at startup (cmd/hsm-pki-server).
const (
	// ContentTypeCert is RFC 2585 §3's type for a single DER certificate.
	ContentTypeCert = "application/pkix-cert"
	// ContentTypeCRL is RFC 2585 §3's type for a single DER CRL.
	ContentTypeCRL = "application/pkix-crl"
)

// RootArtifacts are the ceremony-produced, public artifacts the service
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
//
// Both are DER, the encoding a relying party following those URLs expects —
// see the content-type constants above.
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
	// The certificate's own DER, served as-is at the AIA CA-Issuers URL.
	// No encoding step: x509.Certificate.Raw is already exactly the octets
	// RFC 2585 says belong at that URL.
	if issuer != nil && issuer.Certificate() != nil {
		s.intermediateDER = issuer.Certificate().Raw
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealthz)
	mux.HandleFunc("GET /readyz", s.handleReadyz)
	mux.HandleFunc("POST /certificates", s.handleIssueCertificate)
	mux.HandleFunc("POST /certificates/{serial}/revoke", s.handleRevoke)
	mux.HandleFunc("GET "+CRLPath, s.handleCRL)
	// The issuer side of every leaf's AIA CA-Issuers pointer. A relying
	// party holding only a leaf follows it to build the path upward; the
	// leaf itself says where to look, and this is where it points.
	mux.HandleFunc("GET "+IntermediateCertPath, s.handleIntermediateCert)
	// Static, ceremony-produced artifacts. The paths are fixed and
	// documented so an operator can point the ceremony's -root-crl-url and
	// -root-cert-url at them before the certificates that embed those URLs
	// are ever signed.
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

// handleIntermediateCert serves this service's own intermediate certificate
// at the AIA CA-Issuers URL every leaf it issues points at.
//
// This endpoint is what makes that pointer honest. A leaf carrying a
// CA-Issuers URL that 404s is worse than a leaf carrying none: the first
// tells a relying party the issuer is fetchable and then denies it, the
// second tells it to look elsewhere from the start. The same reasoning is
// why no OCSP pointer is set anywhere in this platform until the responder
// exists (Phase 5b).
func (s *server) handleIntermediateCert(w http.ResponseWriter, r *http.Request) {
	s.serveDERArtifact(w, r, s.intermediateDER, ContentTypeCert, "intermediate certificate")
}

// handleRootCert serves the ceremony-produced root certificate at the AIA
// CA-Issuers URL the intermediate points at.
func (s *server) handleRootCert(w http.ResponseWriter, r *http.Request) {
	s.serveDERArtifact(w, r, s.root.CertDER, ContentTypeCert, "root certificate")
}

// handleRootCRL serves the ceremony-produced root CRL at the distribution
// point the intermediate points at.
//
// It is served verbatim rather than regenerated: producing it requires the
// root's key, which is offline and unreachable from here by design. Its
// validity window is set at ceremony time and is deliberately long, so
// refreshing it means re-running the ceremony (
// phase-3b-pki-hardening.md, "How the root CRL is produced").
func (s *server) handleRootCRL(w http.ResponseWriter, r *http.Request) {
	s.serveDERArtifact(w, r, s.root.CRLDER, ContentTypeCRL, "root CRL")
}

// serveDERArtifact writes one static DER artifact under contentType, or
// fails honestly if it is absent.
//
// The absent case matters more than it looks. cmd/hsm-pki-server validates
// the root artifacts at startup and always has an intermediate certificate
// by then, but NewServer takes both by value and cannot reject a
// zero-valued RootArtifacts or a nil issuer, so an in-process caller can
// construct a server without them. Writing an empty 200 there would be the
// worst outcome available: a relying party fetching the CRL distribution
// point would receive a successful response containing a malformed CRL, and
// the most likely way it handles that is to treat revocation as unavailable
// and carry on. A 503 says the artifact is missing, which is the truth
func (s *server) serveDERArtifact(w http.ResponseWriter, r *http.Request, der []byte, contentType, what string) {
	if len(der) == 0 {
		loggerFromContext(r.Context()).Error("artifact is not available", "artifact", what)
		s.writeError(w, http.StatusServiceUnavailable, what+" is not available on this server")
		return
	}
	w.Header().Set("Content-Type", contentType)
	// These change only when a new ceremony runs, which is a rare,
	// deliberate operator act. An hour is short enough that a re-ceremony
	// propagates on a human timescale and long enough that a CDN is not
	// re-fetching a static file on every request.
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

// handleIssueCertificate implements POST /certificates: accept a PEM or DER
// CSR, validate it, and return the signed certificate. Any rejection —
// malformed body, unparseable CSR, a CSR internal/ca.CA.Issue itself
// rejects, an oversized body — responds before Issue is ever called or
// before its result is recorded, so a bad request is rejected outright,
// never partially processed.
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
			// (failing closed: never leak internal detail to an untrusted
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
	// something unrevocable.
	if err := s.store.Record(r.Context(), store.CertRecord{
		Serial:   cert.SerialNumber,
		Subject:  cert.Subject,
		NotAfter: cert.NotAfter,
		Status:   store.StatusValid,
	}); err != nil {
		// A duplicate serial is not a caller error — serials come from this
		// CA's own crypto/rand, so it means either an astronomically
		// improbable collision or a defect here. Either way the certificate
		// is not handed out, because the store already holds a different
		// record under that serial and revoking it later would be ambiguous.
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

	if err := s.store.Revoke(r.Context(), serial, store.RevocationReason(req.Reason), time.Now()); err != nil {
		if errors.Is(err, store.ErrCertNotFound) {
			s.writeError(w, http.StatusNotFound, "certificate not found")
			return
		}
		// A reason code outside RFC 5280 §5.3.1 is a statement about the
		// caller's request, not about this server: reject it as a 400
		// rather than writing an entry no verifier can interpret into the
		// CRL.
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
	// Bound any intermediary's caching by the CRL's own nextUpdate.
	//
	// This is a correctness control, not a performance one. Without an
	// explicit lifetime, a CDN or proxy applies its own heuristic and may
	// keep serving a CRL past the point this CA said it stops being
	// authoritative — which is indistinguishable, to a relying party, from
	// a CA that has not revoked anything. must-revalidate says the stale
	// copy may not be served once it expires, even if the origin is
	// unreachable.
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
// # The lock is held across generation on purpose
//
// Signing a CRL is an HSM round trip, and holding crlMu for its duration
// looks like a mistake worth "optimizing" with a read-write lock and a
// double-checked cache read. It is not: holding it is what makes this
// single-flight. Ten concurrent GET /crl on a cold cache produce one HSM
// signature and nine waiters, not ten signatures. Releasing the lock to let
// readers through would turn a cache miss into a thundering herd against
// the token — far more expensive than the nanoseconds a cache hit spends
// acquiring an uncontended mutex.
//
// Change this only with a measurement showing cache-hit contention is real,
// and keep the single-flight property if you do (golang.org/x/sync's
// singleflight is the shape that preserves it).
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
	// A CRL may not promise to be authoritative past the point its issuer
	// stops being able to sign anything at all. Clamping rather than
	// refusing, which is the opposite of what Issue does with the same
	// overrun, and deliberately so: a shortened CRL is completely valid and
	// simply asks the verifier to come back sooner, whereas a shortened
	// *certificate* would hand its holder a lifetime they did not ask for.
	// Refusing here would instead remove the CA's ability to publish
	// revocations during the very window in which its expiry makes
	// re-issuance most likely.
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
// safe to return to the caller. Every rejection reason listed below maps to
// 400 — each is a statement about the caller's own CSR, not internal server
// state; anything unrecognized maps to 500 with no detail exposed.
//
// ca.ErrNoDistributionPoints is deliberately not in the list, despite being
// a named error Issue returns. It says this CA has nowhere to publish
// revocation for what it signs, which is a fact about this server's
// configuration and nothing the caller did — a 4xx would tell them to fix
// their request, which cannot help.
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
