// Package token issues and parses the HS256 session tokens returned by
// POST /auth.
package token

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// minSecretLen is the shortest HS256 secret accepted, matching the check in
// internal/config.
const minSecretLen = 32

// Errors returned by Parse. A caller must not be told which check failed
// beyond these two classes.
var (
	// ErrTokenInvalid means the token is malformed, signed with the wrong key,
	// or signed with an algorithm other than HS256.
	ErrTokenInvalid = errors.New("token is invalid")
	// ErrTokenExpired means the token parsed and verified but has expired.
	ErrTokenExpired = errors.New("token has expired")
)

// Claims are the SEP-10 session claims.
type Claims struct {
	jwt.RegisteredClaims
	// ClientDomain is set only when a client domain was verified.
	ClientDomain string `json:"client_domain,omitempty"`
}

// IssuerConfig configures an Issuer.
type IssuerConfig struct {
	// Secret is the HS256 signing secret. Never logged.
	Secret []byte
	// Issuer is the iss claim.
	Issuer string
	// Lifetime is how long an issued token is valid.
	Lifetime time.Duration
}

// Issuer mints and verifies session tokens.
type Issuer struct {
	cfg IssuerConfig
}

// NewIssuer validates the configuration and returns an Issuer.
func NewIssuer(cfg IssuerConfig) (*Issuer, error) {
	if len(cfg.Secret) < minSecretLen {
		// Deliberately does not include the value.
		return nil, fmt.Errorf("jwt secret must be at least %d bytes", minSecretLen)
	}
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("jwt issuer is required")
	}
	if cfg.Lifetime <= 0 {
		return nil, fmt.Errorf("jwt lifetime must be positive")
	}
	return &Issuer{cfg: cfg}, nil
}

// Request describes one token to mint.
type Request struct {
	// Account is the authenticated account, G... or M...
	Account string
	// Memo is the ID memo, when one was used. Never set for a muxed account.
	Memo *uint64
	// ClientDomain is set only when a client domain was verified.
	ClientDomain string
	// JTI is the hex-encoded hash of the challenge transaction envelope.
	JTI string
	// IssuedAt is the iat claim. Passed in rather than read from the clock so
	// tests construct any token they need without a clock seam in production.
	IssuedAt time.Time
}

// Issue returns a signed token for the request.
func (i *Issuer) Issue(req Request) (string, error) {
	if req.Account == "" {
		return "", fmt.Errorf("account is required")
	}
	if req.JTI == "" {
		return "", fmt.Errorf("jti is required")
	}

	claims := Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    i.cfg.Issuer,
			Subject:   Subject(req.Account, req.Memo),
			ID:        req.JTI,
			IssuedAt:  jwt.NewNumericDate(req.IssuedAt),
			ExpiresAt: jwt.NewNumericDate(req.IssuedAt.Add(i.cfg.Lifetime)),
		},
		ClientDomain: req.ClientDomain,
	}

	signed, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(i.cfg.Secret)
	if err != nil {
		return "", fmt.Errorf("signing token: %w", err)
	}
	return signed, nil
}

// Parse verifies a token as of now and returns its claims.
//
// Only HS256 is accepted. Allowing the token's own header to choose the
// algorithm is the classic JWT forgery, so the accepted set is fixed here and
// the key function ignores the header entirely.
func (i *Issuer) Parse(raw string, now time.Time) (*Claims, error) {
	var claims Claims

	_, err := jwt.ParseWithClaims(raw, &claims,
		func(*jwt.Token) (any, error) { return i.cfg.Secret, nil },
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer(i.cfg.Issuer),
		jwt.WithExpirationRequired(),
		jwt.WithTimeFunc(func() time.Time { return now }),
	)
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, fmt.Errorf("%w", ErrTokenExpired)
		}
		return nil, fmt.Errorf("%w", ErrTokenInvalid)
	}

	return &claims, nil
}

// Subject formats the sub claim: the muxed address for an M... account, the
// address and memo joined by a colon when a memo was used, and the plain
// address otherwise.
func Subject(account string, memo *uint64) string {
	if memo == nil {
		return account
	}
	return account + ":" + strconv.FormatUint(*memo, 10)
}
