package api

import (
	"context"
	"net/http"
	"time"

	pk11 "github.com/LockedWayi/hsm-pki-platform/internal/pkcs11"
)

// readyzProbeTimeout bounds the HSM check /readyz performs.
const readyzProbeTimeout = 3 * time.Second

// handleHealthz implements GET /healthz: process liveness only. It must
// never depend on the HSM — a transient HSM blip should not make an
// orchestrator restart an otherwise-healthy pod
func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleReadyz implements GET /readyz: report not-ready when the adapter
// cannot serve, so an orchestrator stops routing traffic here. The probe
// opens and immediately closes a session against the configured
// workspace — no login/PIN needed — which is enough to prove the module is
// loaded and reachable, and correctly reports not-ready once the adapter
// has been closed (every VendorAdapter method returns ErrAdapterClosed
// after Close, including OpenSession).
func (s *server) handleReadyz(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readyzProbeTimeout)
	defer cancel()

	session, err := s.adapter.OpenSession(ctx, s.workspace, pk11.SessionOptions{
		IdleTimeout: readyzProbeTimeout,
		MaxTTL:      readyzProbeTimeout,
	})
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "HSM adapter not ready")
		return
	}
	_ = s.adapter.CloseSession(ctx, session)

	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ready"))
}
