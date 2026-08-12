package httpapi

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/0dillon/Anchorage/internal/store"
	"github.com/0dillon/Anchorage/internal/token"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

// ChallengeStore is the persistence the handlers need. It is declared here,
// where it is called, and satisfied by *store.Postgres.
type ChallengeStore interface {
	// RecordChallenge stores a newly issued challenge.
	RecordChallenge(ctx context.Context, rec store.ChallengeRecord) error
	// ConsumeChallenge marks a nonce used and returns what it was issued for.
	// A second call for the same nonce must fail.
	ConsumeChallenge(ctx context.Context, nonce string, now time.Time) (*store.ConsumedChallenge, error)
	// RecordSession stores an issued token.
	RecordSession(ctx context.Context, rec store.SessionRecord) error
}

// Pinger reports whether a dependency is reachable.
type Pinger interface {
	Ping(ctx context.Context) error
}

// Deps holds everything the routes need. NewRouter checks only the fields the
// mounted routes actually use, so a route added later brings its own check
// with it.
type Deps struct {
	Logger *slog.Logger

	// Issuer builds and signs challenges. Required by GET /auth.
	Issuer *auth.Issuer
	// Tokens mints session tokens. Required by POST /auth.
	Tokens *token.Issuer
	// Accounts looks up signers and thresholds. Required by POST /auth.
	Accounts auth.AccountFetcher
	// Challenges persists challenges and sessions. Required by both /auth
	// routes.
	Challenges ChallengeStore
	// Health backs GET /health.
	Health Pinger

	// NetworkPassphrase is the network challenges are built for.
	NetworkPassphrase string
	// WebAuthDomain is the domain hosting this service. A challenge naming a
	// different one is not ours.
	WebAuthDomain string
	// HomeDomains is the set of home domains this server authenticates for.
	HomeDomains []string
	// TOMLPath is the SEP-1 file served at /.well-known/stellar.toml.
	TOMLPath string
	// SigningPublicKey is substituted into the SEP-1 file's SIGNING_KEY.
	SigningPublicKey string
	// TrustProxyHeaders mounts chi's RealIP middleware, so X-Forwarded-For and
	// X-Real-IP decide which client the rate limit applies to. Leave it false
	// unless a proxy under your control overwrites those headers: they are
	// caller-supplied, and believing them otherwise makes the rate limit
	// bypassable with one header.
	TrustProxyHeaders bool
}

// NewRouter wires the routes. It returns an error rather than panicking so a
// misconfigured server fails at startup with a message.
func NewRouter(d Deps) (http.Handler, error) {
	if d.Logger == nil {
		return nil, fmt.Errorf("a logger is required")
	}
	if d.Health == nil {
		return nil, fmt.Errorf("a health pinger is required")
	}

	limiter := newRateLimiter(requestsPerMinute)

	r := chi.NewRouter()
	r.Use(middleware.RequestID)
	// RealIP rewrites RemoteAddr from X-Forwarded-For and X-Real-IP, and it
	// believes them unconditionally. Those headers come from the caller, so
	// mounting it when nothing overwrites them upstream would let anyone send a
	// fresh address per request and walk past the per-IP rate limit, as well as
	// write whatever they liked into the logs. It is therefore mounted only when
	// the operator states that a proxy they control is rewriting the headers.
	// Without that, the rate limit keys on the real TCP peer.
	if d.TrustProxyHeaders {
		r.Use(middleware.RealIP)
	}
	r.Use(recoverPanic(d.Logger))
	r.Use(requestLogger(d.Logger))
	r.Use(limitBody)
	r.Use(limiter.middleware(d.Logger))

	r.Get("/health", healthHandler(d.Health, d.Logger))

	return r, nil
}
