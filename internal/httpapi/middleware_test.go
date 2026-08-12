package httpapi

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// discardLogger keeps test output clean while still exercising the logging
// path.
func discardLogger() *slog.Logger {
	return slog.New(slog.NewJSONHandler(io.Discard, nil))
}

// captureLogger returns a logger and the buffer it writes to.
func captureLogger() (*slog.Logger, *bytes.Buffer) {
	buf := &bytes.Buffer{}
	return slog.New(slog.NewJSONHandler(buf, nil)), buf
}

func TestLimitBodyRejectsOversizedRequest(t *testing.T) {
	handler := limitBody(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, err := io.ReadAll(r.Body); err != nil {
			w.WriteHeader(http.StatusRequestEntityTooLarge)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))

	tests := []struct {
		name string
		size int
		want int
	}{
		{"within the cap", maxBodyBytes - 1, http.StatusOK},
		{"over the cap", maxBodyBytes + 1, http.StatusRequestEntityTooLarge},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := strings.NewReader(strings.Repeat("a", tt.size))
			req := httptest.NewRequest(http.MethodPost, "/auth", body)
			rec := httptest.NewRecorder()

			handler.ServeHTTP(rec, req)
			require.Equal(t, tt.want, rec.Code)
		})
	}
}

// A panic becomes a 500 with a JSON body, and the panic value is logged but
// never sent to the client.
func TestRecoverPanic(t *testing.T) {
	logger, logs := captureLogger()

	handler := recoverPanic(logger)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			panic("secret internal detail")
		}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth", nil))

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	require.NotContains(t, rec.Body.String(), "secret internal detail")

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, "internal server error", body["error"])

	// The operator still gets the detail.
	require.Contains(t, logs.String(), "secret internal detail")
}

// The logger records the outcome and never the query string, which carries the
// caller's account and client domain.
func TestRequestLoggerRecordsOutcome(t *testing.T) {
	logger, logs := captureLogger()

	handler := requestLogger(logger)(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusTeapot)
		}))

	req := httptest.NewRequest(http.MethodGet, "/auth?account=GABC&client_domain=wallet.example.org", nil)
	handler.ServeHTTP(httptest.NewRecorder(), req)

	var entry map[string]any
	require.NoError(t, json.Unmarshal(logs.Bytes(), &entry))
	require.Equal(t, "GET", entry["method"])
	require.Equal(t, "/auth", entry["path"])
	require.Equal(t, float64(http.StatusTeapot), entry["status"])
	require.NotContains(t, logs.String(), "wallet.example.org")
}

// The bucket refills over time and is capped at the burst size.
func TestRateLimiter(t *testing.T) {
	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	limiter := newRateLimiter(60)

	// The burst is the per-minute allowance, so the first 60 are allowed and
	// the 61st in the same instant is not.
	for i := range 60 {
		require.True(t, limiter.allow("1.2.3.4", base), "request %d should be allowed", i)
	}
	require.False(t, limiter.allow("1.2.3.4", base))

	// One second later exactly one token has refilled.
	require.True(t, limiter.allow("1.2.3.4", base.Add(time.Second)))
	require.False(t, limiter.allow("1.2.3.4", base.Add(time.Second)))

	// A different address has its own bucket.
	require.True(t, limiter.allow("5.6.7.8", base))

	// The bucket never refills past the burst, however long it idles.
	for i := range 60 {
		require.True(t, limiter.allow("1.2.3.4", base.Add(time.Hour)), "request %d should be allowed", i)
	}
	require.False(t, limiter.allow("1.2.3.4", base.Add(time.Hour)))
}

func TestRateLimitMiddlewareReturns429(t *testing.T) {
	limiter := newRateLimiter(1)
	handler := limiter.middleware(discardLogger())(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
		}))

	newReq := func() *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/auth", nil)
		req.RemoteAddr = "1.2.3.4:5678"
		return req
	}

	first := httptest.NewRecorder()
	handler.ServeHTTP(first, newReq())
	require.Equal(t, http.StatusOK, first.Code)

	second := httptest.NewRecorder()
	handler.ServeHTTP(second, newReq())
	require.Equal(t, http.StatusTooManyRequests, second.Code)
}

// With TrustProxyHeaders false, a forged X-Forwarded-For must not buy a fresh
// rate-limit bucket. Every request here comes from one TCP peer, so the bucket
// runs out however the header changes.
func TestRateLimitIgnoresForgedForwardedHeaderByDefault(t *testing.T) {
	deps, _ := newTestDeps(t)
	deps.Health = fakePinger{}
	router, err := NewRouter(deps)
	require.NoError(t, err)

	newReq := func(forwarded string) *http.Request {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "1.2.3.4:5678"
		req.Header.Set("X-Forwarded-For", forwarded)
		return req
	}

	// Spend the whole bucket, presenting a different forged address each time.
	for i := range requestsPerMinute {
		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, newReq(fmt.Sprintf("10.0.0.%d", i%256)))
		require.Equal(t, http.StatusOK, rec.Code, "request %d", i)
	}

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, newReq("10.9.9.9"))
	require.Equal(t, http.StatusTooManyRequests, rec.Code)
}

// The mirror image, and the control: with TrustProxyHeaders true, RealIP is
// mounted and each forwarded address gets its own bucket, so more than a
// bucket's worth of requests all succeed. Without this test the one above would
// still pass if the gate ignored its setting and never mounted RealIP at all.
func TestRateLimitHonoursForwardedHeaderWhenTrusted(t *testing.T) {
	deps, _ := newTestDeps(t)
	deps.Health = fakePinger{}
	deps.TrustProxyHeaders = true
	router, err := NewRouter(deps)
	require.NoError(t, err)

	for i := range requestsPerMinute + 5 {
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.RemoteAddr = "1.2.3.4:5678"
		req.Header.Set("X-Forwarded-For", fmt.Sprintf("10.1.%d.%d", i/256, i%256))

		rec := httptest.NewRecorder()
		router.ServeHTTP(rec, req)
		require.Equal(t, http.StatusOK, rec.Code, "request %d", i)
	}
}

// Idle buckets are dropped, so a long-running server does not accumulate one
// map entry per address it has ever seen.
func TestRateLimiterSweepsIdleBuckets(t *testing.T) {
	base := time.Date(2026, 8, 10, 12, 0, 0, 0, time.UTC)
	limiter := newRateLimiter(60)

	require.True(t, limiter.allow("1.2.3.4", base))
	require.Len(t, limiter.buckets, 1)

	require.True(t, limiter.allow("5.6.7.8", base.Add(2*bucketIdleTTL)))
	require.Len(t, limiter.buckets, 1)
	require.Contains(t, limiter.buckets, "5.6.7.8")
}
