package httpapi

import (
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/go-chi/chi/v5/middleware"
)

const (
	// maxBodyBytes caps a request body. No SEP-10 request is near this size; a
	// challenge envelope is a few kilobytes.
	maxBodyBytes = 64 * 1024

	// requestsPerMinute is the per-IP rate limit. It is fixed rather than
	// configurable on purpose: it guards against casual abuse, and an operator
	// fronting this with a real gateway will set their own policy there.
	requestsPerMinute = 60

	// bucketIdleTTL is how long an unused rate-limit bucket is kept.
	bucketIdleTTL = 10 * time.Minute

	// sweepInterval is the shortest gap between sweeps of idle buckets.
	sweepInterval = time.Minute
)

// limitBody caps the request body. Reads past the cap fail in the handler,
// which is where the error can still be turned into a response.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		next.ServeHTTP(w, r)
	})
}

// requestLogger logs one line per request after it completes.
//
// The path is logged; the query string is not. On GET /auth the query carries
// the caller's account and client domain, and neither belongs in a log file.
func requestLogger(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			started := time.Now()
			wrapped := middleware.NewWrapResponseWriter(w, r.ProtoMajor)

			next.ServeHTTP(wrapped, r)

			logger.Info("request",
				"method", r.Method,
				"path", r.URL.Path,
				"status", wrapped.Status(),
				"bytes", wrapped.BytesWritten(),
				"duration_ms", time.Since(started).Milliseconds(),
				"request_id", middleware.GetReqID(r.Context()),
			)
		})
	}
}

// recoverPanic turns a panic into a 500 and logs it. The panic value is for
// the operator; the client is told only that something failed.
func recoverPanic(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				recovered := recover()
				if recovered == nil {
					return
				}
				// http.ErrAbortHandler is the standard library's way of saying
				// the response was deliberately abandoned. Re-panic so the
				// server handles it as intended.
				if recovered == http.ErrAbortHandler {
					panic(recovered)
				}

				logger.Error("panic recovered",
					"panic", recovered,
					"path", r.URL.Path,
					"request_id", middleware.GetReqID(r.Context()),
				)
				writeError(w, logger, http.StatusInternalServerError, "internal server error")
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// rateLimiter is a per-key token bucket held in this process. It is not shared
// between instances; behind a load balancer each instance enforces its own.
type rateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	perSecond float64
	burst     float64
	lastSweep time.Time
}

type bucket struct {
	tokens float64
	last   time.Time
}

// newRateLimiter returns a limiter allowing perMinute requests per key per
// minute, with a burst of the same size.
func newRateLimiter(perMinute int) *rateLimiter {
	return &rateLimiter{
		buckets:   make(map[string]*bucket),
		perSecond: float64(perMinute) / 60,
		burst:     float64(perMinute),
	}
}

// allow reports whether the key may make a request at the given time, and
// spends a token if it may.
func (l *rateLimiter) allow(key string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.sweep(now)

	b, ok := l.buckets[key]
	if !ok {
		b = &bucket{tokens: l.burst, last: now}
		l.buckets[key] = b
	}

	// Refill for the time since the last request, capped at the burst.
	elapsed := now.Sub(b.last).Seconds()
	if elapsed > 0 {
		b.tokens += elapsed * l.perSecond
		if b.tokens > l.burst {
			b.tokens = l.burst
		}
		b.last = now
	}

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// sweep drops buckets that have been idle longer than bucketIdleTTL, so the
// map does not grow once per address the server has ever seen. The caller
// holds the lock.
func (l *rateLimiter) sweep(now time.Time) {
	if now.Sub(l.lastSweep) < sweepInterval {
		return
	}
	l.lastSweep = now

	for key, b := range l.buckets {
		if now.Sub(b.last) > bucketIdleTTL {
			delete(l.buckets, key)
		}
	}
}

// middleware applies the limit per client address.
func (l *rateLimiter) middleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !l.allow(clientIP(r), time.Now()) {
				writeError(w, logger, http.StatusTooManyRequests, "too many requests")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// clientIP returns the address to rate-limit on. chi's RealIP middleware has
// already applied any forwarded headers, so RemoteAddr is the right source
// here.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
