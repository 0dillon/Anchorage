package clientdomain

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

const signingKey = "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H"

// newTestResolver points a resolver at a test server. The url builder is
// overridden because httptest serves plain HTTP; the HTTPS rule itself is
// tested separately, through the exported path.
func newTestResolver(t *testing.T, ttl time.Duration, h http.Handler) (*Resolver, *int) {
	t.Helper()

	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		h.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)

	r := NewResolver(ResolverConfig{CacheTTL: ttl, Client: srv.Client()})
	r.urlFor = func(domain string) string { return srv.URL + "/.well-known/stellar.toml" }
	return r, &calls
}

func tomlHandler(body string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte(body))
	})
}

func TestResolveReadsSigningKey(t *testing.T) {
	r, calls := newTestResolver(t, time.Minute, tomlHandler(
		"VERSION=\"2.0.0\"\nSIGNING_KEY=\""+signingKey+"\"\n"))

	got, err := r.Resolve(context.Background(), "wallet.example.org")
	require.NoError(t, err)
	require.Equal(t, signingKey, got)
	require.Equal(t, 1, *calls)
}

func TestResolveRejectsBadTOML(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{"no signing key", "VERSION=\"2.0.0\"\n"},
		{"empty signing key", "SIGNING_KEY=\"\"\n"},
		{"signing key is not a strkey", "SIGNING_KEY=\"not-a-key\"\n"},
		{"signing key is a secret seed", "SIGNING_KEY=\"SBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7O5RT\"\n"},
		{"body is not toml", "<html>404 not found</html>\n"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r, _ := newTestResolver(t, time.Minute, tomlHandler(tt.body))

			_, err := r.Resolve(context.Background(), "wallet.example.org")
			require.Error(t, err)
			// The domain is named; the body is never echoed back.
			require.Contains(t, err.Error(), "wallet.example.org")
			require.NotContains(t, err.Error(), tt.body)
		})
	}
}

func TestResolveRejectsNon200(t *testing.T) {
	r, _ := newTestResolver(t, time.Minute, http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))

	_, err := r.Resolve(context.Background(), "wallet.example.org")
	require.Error(t, err)
	require.Contains(t, err.Error(), "404")
}

func TestResolveRejectsOversizedBody(t *testing.T) {
	body := strings.Repeat("# padding\n", (maxTOMLBytes/10)+1)
	r, _ := newTestResolver(t, time.Minute, tomlHandler(body))

	_, err := r.Resolve(context.Background(), "wallet.example.org")
	require.Error(t, err)
	require.Contains(t, err.Error(), "too large")
}

// A success is cached, so a second call inside the TTL makes no request.
func TestResolveCachesSuccess(t *testing.T) {
	r, calls := newTestResolver(t, time.Minute, tomlHandler(
		"SIGNING_KEY=\""+signingKey+"\"\n"))

	for range 3 {
		got, err := r.Resolve(context.Background(), "wallet.example.org")
		require.NoError(t, err)
		require.Equal(t, signingKey, got)
	}
	require.Equal(t, 1, *calls)
}

// A stale entry is refetched. The TTL is one nanosecond, so the entry written
// by the first call is already expired by the second. No sleep, no clock seam.
func TestResolveRefetchesAfterTTL(t *testing.T) {
	r, calls := newTestResolver(t, time.Nanosecond, tomlHandler(
		"SIGNING_KEY=\""+signingKey+"\"\n"))

	_, err := r.Resolve(context.Background(), "wallet.example.org")
	require.NoError(t, err)
	_, err = r.Resolve(context.Background(), "wallet.example.org")
	require.NoError(t, err)

	require.Equal(t, 2, *calls)
}

// Failures are not cached, so a domain that recovers is picked up at once.
func TestResolveDoesNotCacheFailures(t *testing.T) {
	fail := true
	r, calls := newTestResolver(t, time.Minute, http.HandlerFunc(
		func(w http.ResponseWriter, req *http.Request) {
			if fail {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_, _ = w.Write([]byte("SIGNING_KEY=\"" + signingKey + "\"\n"))
		}))

	_, err := r.Resolve(context.Background(), "wallet.example.org")
	require.Error(t, err)

	fail = false
	got, err := r.Resolve(context.Background(), "wallet.example.org")
	require.NoError(t, err)
	require.Equal(t, signingKey, got)
	require.Equal(t, 2, *calls)
}

// An allowlisted resolver rejects an unlisted domain before any network call.
func TestResolveEnforcesAllowlist(t *testing.T) {
	r, calls := newTestResolver(t, time.Minute, tomlHandler(
		"SIGNING_KEY=\""+signingKey+"\"\n"))
	r.allowlist = map[string]bool{"allowed.example.org": true}

	_, err := r.Resolve(context.Background(), "wallet.example.org")
	require.Error(t, err)
	require.Contains(t, err.Error(), "not on the allowlist")
	require.Equal(t, 0, *calls)

	_, err = r.Resolve(context.Background(), "allowed.example.org")
	require.NoError(t, err)
	require.Equal(t, 1, *calls)
}

// The cache is bounded. Distinct domains cost a caller nothing to generate, so
// an unbounded map would grow for as long as it kept asking.
func TestResolveCacheIsBounded(t *testing.T) {
	r, calls := newTestResolver(t, time.Minute, tomlHandler(
		"SIGNING_KEY=\""+signingKey+"\"\n"))

	for i := range maxCacheEntries + 10 {
		_, err := r.Resolve(context.Background(), fmt.Sprintf("d%d.example.org", i))
		require.NoError(t, err)
	}

	r.mu.Lock()
	size := len(r.cache)
	r.mu.Unlock()

	require.LessOrEqual(t, size, maxCacheEntries)
	// Every domain was distinct, so every one was fetched and none was served
	// from the cache.
	require.Equal(t, maxCacheEntries+10, *calls)
}

// An expired entry is dropped on the next write rather than kept for the life of
// the process.
func TestResolvePurgesExpiredEntries(t *testing.T) {
	r, _ := newTestResolver(t, time.Nanosecond, tomlHandler(
		"SIGNING_KEY=\""+signingKey+"\"\n"))

	_, err := r.Resolve(context.Background(), "first.example.org")
	require.NoError(t, err)
	_, err = r.Resolve(context.Background(), "second.example.org")
	require.NoError(t, err)

	r.mu.Lock()
	_, firstStillCached := r.cache["first.example.org"]
	r.mu.Unlock()

	require.False(t, firstStillCached, "an expired entry must be purged on the next write")
}

func TestResolveRejectsEmptyDomain(t *testing.T) {
	r, calls := newTestResolver(t, time.Minute, tomlHandler(""))

	_, err := r.Resolve(context.Background(), "")
	require.Error(t, err)
	require.Equal(t, 0, *calls)
}

// The default url builder is HTTPS and nothing can change it from outside the
// package. This is the test that pins the exported behaviour.
func TestDefaultURLIsHTTPS(t *testing.T) {
	r := NewResolver(ResolverConfig{CacheTTL: time.Minute})
	require.Equal(t,
		"https://wallet.example.org/.well-known/stellar.toml",
		r.urlFor("wallet.example.org"))
}

// A redirect to plain HTTP is refused, and so is a redirect chain longer than
// three hops.
func TestRedirectPolicy(t *testing.T) {
	tests := []struct {
		name string
		via  int
		url  string
		ok   bool
	}{
		{"first https hop", 0, "https://a.example.org/x", true},
		{"third https hop", 2, "https://a.example.org/x", true},
		{"fourth https hop", 3, "https://a.example.org/x", false},
		{"http hop", 0, "http://a.example.org/x", false},
		{"non-http scheme", 0, "file:///etc/passwd", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tt.url, nil)
			via := make([]*http.Request, tt.via)

			err := checkRedirect(req, via)
			if tt.ok {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
		})
	}
}
