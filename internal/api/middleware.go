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
// not math/rand — the standard-library rule states randomness is always crypto/rand
// with no exceptions, and a request id is not worth carving one out for.
//
// The error is handled rather than discarded. A failed read leaves b as
// all zeros, which would silently assign every concurrent request the same
// id "0000000000000000" — the one outcome that defeats the entire purpose
// of a correlation id, and it would appear exactly when logs matter most.
// The fallback is monotonic rather than random: it cannot collide, which is
// the property actually needed here. This is not security-critical (the id
// authorizes nothing), so degrading to a counter is correct where failing
// the request would not be.
func newRequestID() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return fmt.Sprintf("seq-%016x", requestIDFallback.Add(1))
	}
	return hex.EncodeToString(b)
}

// requestIDFallback backs newRequestID when crypto/rand is unavailable.
var requestIDFallback atomic.Uint64

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
