package api

import (
	"context"
	"net/http"
	"time"

	pk11 "github.com/LockedWayi/multivendor-hsm-pki/internal/pkcs11"
)

// readyzProbeTimeout bounds the HSM check /readyz performs.
const readyzProbeTimeout = 3 * time.Second

// handleHealthz implements GET /healthz: process liveness only. It never
// touches the token, so a transient HSM failure does not make an
// orchestrator restart the pod.
func (s *server) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok"))
}

// handleReadyz implements GET /readyz. It opens and closes a session on
// the configured workspace, with no login, which shows the module is
// loaded and reachable, and reports not ready once the adapter is closed.
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
