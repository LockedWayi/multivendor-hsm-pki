package api

import (
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

// ContentTypeOCSPRequest and ContentTypeOCSPResponse are the media types
// RFC 6960 appendix A gives for the two halves of the exchange.
const (
	ContentTypeOCSPRequest  = "application/ocsp-request"
	ContentTypeOCSPResponse = "application/ocsp-response"
)

// maxOCSPRequestBytes bounds a request body. A request is a serial and
// two hashes; anything larger is not one.
const maxOCSPRequestBytes = 4096

// handleOCSPPost implements POST /ocsp: the DER request is the body.
func (s *server) handleOCSPPost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxOCSPRequestBytes+1))
	if err != nil || len(body) > maxOCSPRequestBytes {
		s.writeError(w, http.StatusBadRequest, "reading the OCSP request")
		return
	}
	s.serveOCSP(w, r, body)
}

// handleOCSPGet implements GET /ocsp/{request}: the request is the DER
// base64-encoded and then URL-encoded (RFC 5019 §5). The mux hands the
// path back already unescaped, so a second unescape is only for clients
// that encoded twice, and a body that fails to decode is a malformed
// request in OCSP's own terms, not an HTTP error.
func (s *server) handleOCSPGet(w http.ResponseWriter, r *http.Request) {
	raw := r.PathValue("request")
	if unescaped, err := url.PathUnescape(raw); err == nil {
		raw = unescaped
	}
	der, err := base64.StdEncoding.DecodeString(raw)
	if err != nil {
		der = nil // Respond turns an empty request into malformedRequest.
	}
	s.serveOCSP(w, r, der)
}

// serveOCSP answers one request and sets the headers RFC 5019 §6.2 asks
// a responder to set: a cache lifetime bound to the response's own
// nextUpdate for a definitive answer, and no caching for an error
// response, which is a statement about the responder's state rather
// than the certificate's.
func (s *server) serveOCSP(w http.ResponseWriter, r *http.Request, reqDER []byte) {
	der, outcome := s.responder.Respond(r.Context(), reqDER)
	w.Header().Set("Content-Type", ContentTypeOCSPResponse)
	if outcome.Error != "" {
		loggerFromContext(r.Context()).Info("OCSP error response", "error", outcome.Error)
		w.Header().Set("Cache-Control", "no-store")
	} else {
		maxAge := int(time.Until(outcome.NextUpdate).Seconds())
		if maxAge < 0 {
			maxAge = 0
		}
		w.Header().Set("Cache-Control", fmt.Sprintf("public, max-age=%d, must-revalidate", maxAge))
		loggerFromContext(r.Context()).Info("OCSP response", "status", outcome.Status, "cached", outcome.Cached)
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(der)
}
