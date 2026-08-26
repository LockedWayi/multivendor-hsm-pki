// Package api implements the CA's HTTP surface: certificate issuance,
// revocation, CRL distribution, and health/readiness endpoints. Routes are
// added incrementally as the phase that owns them lands (see
// docs/phases/phase-2-ca-core.md) — this file only wires the mux itself, so
// cmd/hsm-pki-server has something to serve and shut down gracefully from
// the first sub-task, before any route exists.
package api

import "net/http"

// NewServer builds the HTTP handler for the CA service. Routes are
// registered here as each owning sub-task implements them.
func NewServer() http.Handler {
	mux := http.NewServeMux()
	return mux
}
