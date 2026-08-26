package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"time"
)

type ctxKey int

const loggerCtxKey ctxKey = iota

// withRequestLogging wraps next so every request logs its method, path,
// status, and duration under one consistent set of field names, and so
// handlers can pull a request-scoped logger — annotated with a request id,
// so every log line from one request can be correlated — out of the
// request context instead of reaching for a bare package-level logger.
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

// loggerFromContext returns the request-scoped logger withRequestLogging
// attached, or slog.Default() when called outside a request it wrapped
// (e.g. a handler invoked directly in a unit test).
func loggerFromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(loggerCtxKey).(*slog.Logger); ok {
		return l
	}
	return slog.Default()
}

// newRequestID returns a short, unpredictable correlation id. crypto/rand,
// not math/rand — CLAUDE.md §3.3 states randomness is always crypto/rand
// with no exceptions, and a request id is not worth carving one out for.
func newRequestID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// statusRecorder captures the status code a handler wrote, so the logging
// middleware can report it after the handler has already written the
// response.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}
