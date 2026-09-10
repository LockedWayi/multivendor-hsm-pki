package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"
)

type ctxKey int

const loggerCtxKey ctxKey = iota

// withRequestLogging logs every request's method, path, status and
// duration, and puts a request-scoped logger carrying a request id into
// the context for handlers.
func withRequestLogging(base *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqLogger := base.With(
			"request_id", newRequestID(),
			"method", r.Method,
			"path", r.URL.Path,
		)
		ctx := context.WithValue(r.Context(), loggerCtxKey, reqLogger)

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		start := time.Now()
		next.ServeHTTP(rec, r.WithContext(ctx))

		reqLogger.Info("request completed",
			"status", rec.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// loggerFromContext returns the request-scoped logger, or slog.Default()
// outside a wrapped request.
func loggerFromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerCtxKey).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

// newRequestID returns a short unpredictable correlation id from
// crypto/rand. A failed read falls back to a counter rather than to all
// zeros, which would give every request the same id. The id authorizes
// nothing, so a counter is acceptable there.
func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("seq-%016x", requestIDFallback.Add(1))
	}
	return hex.EncodeToString(b)
}

// requestIDFallback backs newRequestID when crypto/rand is unavailable.
var requestIDFallback atomic.Uint64

// statusRecorder captures the status code a handler wrote.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

// WriteHeader records the first status written and ignores later ones, as
// net/http does.
func (r *statusRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Write marks the header as written; a bare Write implies a 200.
func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wroteHeader = true
	return r.ResponseWriter.Write(b)
}

// Unwrap exposes the underlying ResponseWriter to http.ResponseController,
// so Flusher, Hijacker and deadline control survive the wrapper.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
