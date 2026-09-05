package api

import (
	"context"
	"encoding/hex"
	"log/slog"
	"math/rand"
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

// newRequestID returns a short correlation id. The id authorizes nothing
// and is only ever read out of a log line, so this uses math/rand: it
// needs no entropy pool and cannot fail, which removes the fallback branch
// that existed only to handle an error crypto/rand could return.
func newRequestID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// statusRecorder captures the status code a handler wrote, so the logging
// middleware can report it after the handler has already written the
// response.
type statusRecorder struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

// WriteHeader records the first status written and ignores later ones, the
// same way net/http itself does. Without the guard, a handler that calls
// WriteHeader twice (which net/http logs and ignores) would leave this
// recorder reporting a status the client never received — the access log
// would disagree with the wire.
func (r *statusRecorder) WriteHeader(code int) {
	if r.wroteHeader {
		return
	}
	r.wroteHeader = true
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// Write marks the header as written, since an unadorned Write implies a
// 200 that WriteHeader never saw.
func (r *statusRecorder) Write(b []byte) (int, error) {
	r.wroteHeader = true
	return r.ResponseWriter.Write(b)
}

// Unwrap exposes the underlying ResponseWriter to http.ResponseController,
// which is how a wrapper preserves capabilities it does not itself
// implement — Flusher, Hijacker, deadline control. Without it, wrapping
// silently strips them from every handler beneath. This service streams
// nothing today; the three lines are what stop that from becoming a
// confusing bug the day something does.
func (r *statusRecorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
