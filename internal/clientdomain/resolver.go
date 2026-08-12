// Package clientdomain resolves the SIGNING_KEY a wallet publishes in its
// SEP-1 stellar.toml.
//
// This is the part of the server most exposed to the outside world: it fetches
// a file from a domain the caller names. Every response is treated as hostile.
// The scheme is HTTPS and stays HTTPS across redirects, the redirect chain is
// bounded, the whole request is bounded by a timeout, and the body is read
// through a cap.
package clientdomain

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/stellar/go-stellar-sdk/strkey"
)

const (
	// maxTOMLBytes caps the stellar.toml body at 100 KB.
	maxTOMLBytes = 100 * 1024
	// maxRedirects is the longest redirect chain followed.
	maxRedirects = 3
	// fetchTimeout bounds the whole request, including redirects.
	fetchTimeout = 5 * time.Second
	// maxCacheEntries caps the cache. A domain is caller-supplied input and
	// wildcard DNS makes distinct domains free to generate, so an unbounded map
	// would grow for as long as a caller kept feeding it new names. A full cache
	// is not a correctness problem: an uncached domain is simply refetched.
	maxCacheEntries = 1024
)

// ResolverConfig configures a Resolver.
type ResolverConfig struct {
	// Allowlist, when non-empty, is the only set of domains that may be
	// resolved. A domain outside it is refused before any network call.
	Allowlist []string
	// CacheTTL is how long a resolved key is reused.
	CacheTTL time.Duration
	// Client is the HTTP client. Nil means a client built to this package's
	// timeout and redirect policy.
	Client *http.Client
}

// Resolver fetches and caches client domain signing keys.
type Resolver struct {
	allowlist map[string]bool
	ttl       time.Duration
	client    *http.Client

	// urlFor builds the stellar.toml URL. It is a field only so tests can
	// point it at an httptest server; nothing outside this package can set it,
	// and the default is always HTTPS.
	urlFor func(domain string) string

	mu    sync.Mutex
	cache map[string]cacheEntry
}

type cacheEntry struct {
	signingKey string
	expiresAt  time.Time
}

// NewResolver returns a Resolver. An empty allowlist means every domain is
// allowed.
func NewResolver(cfg ResolverConfig) *Resolver {
	allowlist := make(map[string]bool, len(cfg.Allowlist))
	for _, domain := range cfg.Allowlist {
		allowlist[domain] = true
	}

	client := cfg.Client
	if client == nil {
		client = &http.Client{Timeout: fetchTimeout}
	}
	// The policy is applied whether or not the caller supplied the client, so a
	// caller cannot hand in a client that follows redirects to plain HTTP. The
	// client is copied before the policy is set: assigning CheckRedirect on the
	// caller's own client would change how that client behaves everywhere else
	// it is used, and a caller passing http.DefaultClient would change it for
	// the whole process. The copy shares the Transport, so the connection pool
	// is still shared.
	policed := *client
	policed.CheckRedirect = checkRedirect
	client = &policed

	return &Resolver{
		allowlist: allowlist,
		ttl:       cfg.CacheTTL,
		client:    client,
		urlFor:    defaultURL,
		cache:     make(map[string]cacheEntry),
	}
}

// defaultURL builds the SEP-1 well-known URL over HTTPS.
func defaultURL(domain string) string {
	return "https://" + domain + "/.well-known/stellar.toml"
}

// checkRedirect refuses a redirect chain longer than maxRedirects and any hop
// that is not HTTPS. A wallet that downgrades to plain HTTP is not trusted to
// state its own signing key.
func checkRedirect(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if req.URL.Scheme != "https" {
		return fmt.Errorf("refusing redirect to non-https scheme %q", req.URL.Scheme)
	}
	return nil
}

// Resolve returns the SIGNING_KEY published by the domain. A cached entry
// inside the TTL is returned without a fetch. Failures are never cached, so a
// domain that recovers is picked up on the next request.
func (r *Resolver) Resolve(ctx context.Context, domain string) (string, error) {
	if domain == "" {
		return "", fmt.Errorf("client domain is empty")
	}
	if len(r.allowlist) > 0 && !r.allowlist[domain] {
		return "", fmt.Errorf("%s is not on the allowlist", domain)
	}

	if key, ok := r.cached(domain); ok {
		return key, nil
	}

	key, err := r.fetch(ctx, domain)
	if err != nil {
		return "", err
	}

	r.store(domain, key)

	return key, nil
}

// store caches a resolved key. Expired entries are dropped first, so the map
// does not keep every domain ever asked about. If the cache is still full the
// new entry is not stored: that costs a refetch next time and never evicts a
// live entry to make room.
func (r *Resolver) store(domain, key string) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := time.Now()
	for cached, entry := range r.cache {
		if !now.Before(entry.expiresAt) {
			delete(r.cache, cached)
		}
	}
	if len(r.cache) >= maxCacheEntries {
		return
	}
	r.cache[domain] = cacheEntry{signingKey: key, expiresAt: now.Add(r.ttl)}
}

// cached returns a live cache entry, if there is one.
func (r *Resolver) cached(domain string) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()

	entry, ok := r.cache[domain]
	if !ok || !time.Now().Before(entry.expiresAt) {
		return "", false
	}
	return entry.signingKey, true
}

// fetch performs one bounded request and parses the result.
func (r *Resolver) fetch(ctx context.Context, domain string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, fetchTimeout)
	defer cancel()

	endpoint := r.urlFor(domain)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("%s: building request: %w", domain, err)
	}
	req.Header.Set("Accept", "text/plain")

	resp, err := r.client.Do(req)
	if err != nil {
		// A *url.Error carries the full URL, which is the caller's own input;
		// it is safe to report, but the message stays short.
		return "", fmt.Errorf("%s: fetching stellar.toml failed", domain)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s: stellar.toml returned %d", domain, resp.StatusCode)
	}

	// One byte over the cap, so an oversized file is rejected rather than
	// truncated. Truncation could change how the file parses.
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxTOMLBytes+1))
	if err != nil {
		return "", fmt.Errorf("%s: reading stellar.toml failed", domain)
	}
	if len(body) > maxTOMLBytes {
		return "", fmt.Errorf("%s: stellar.toml is too large", domain)
	}

	var doc struct {
		SigningKey string `toml:"SIGNING_KEY"`
	}
	if _, err := toml.Decode(string(body), &doc); err != nil {
		// The parse error quotes the offending line, so it is not included.
		return "", fmt.Errorf("%s: stellar.toml is not valid TOML", domain)
	}
	if doc.SigningKey == "" {
		return "", fmt.Errorf("%s: stellar.toml has no SIGNING_KEY", domain)
	}
	if !strkey.IsValidEd25519PublicKey(doc.SigningKey) {
		return "", fmt.Errorf("%s: SIGNING_KEY is not a valid G... address", domain)
	}

	return doc.SigningKey, nil
}
