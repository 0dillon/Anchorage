// Package store persists issued challenges and the sessions they produce.
//
// A challenge is valid exactly once. Consumption is a single atomic statement,
// never a read followed by a write, so two concurrent posts of the same
// challenge cannot both succeed.
package store

import (
	"embed"
	"fmt"
	"net/url"
	"time"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// ChallengeRecord is a challenge as issued, before any client has answered it.
type ChallengeRecord struct {
	// Nonce is the base64 value of the challenge's first manage_data operation.
	Nonce string
	// Account is the account the challenge was issued for, G... or M...
	Account    string
	HomeDomain string
	// ClientDomain is empty when the challenge carried no client_domain.
	ClientDomain string
	IssuedAt     time.Time
	ExpiresAt    time.Time
}

// ConsumedChallenge is what a successful consumption returns. The stored values
// are authoritative: the client cannot change which account or home domain a
// nonce was issued for by editing the transaction it posts back.
type ConsumedChallenge struct {
	Account      string
	HomeDomain   string
	ClientDomain string
}

// SessionRecord is one issued token. Sessions are never deleted; they are the
// audit trail.
type SessionRecord struct {
	// JTI is the token's jti claim, the hex hash of the challenge envelope.
	JTI     string
	Account string
	// Memo is the ID memo as a decimal string, empty when none was used.
	Memo         string
	HomeDomain   string
	ClientDomain string
	IssuedAt     time.Time
	ExpiresAt    time.Time
}

// migrationURL rewrites a Postgres connection string to the scheme the
// golang-migrate database/pgx/v5 driver registers, which is "pgx5". Leaving it
// as postgres:// would select the lib/pq-backed driver, which this project does
// not depend on.
//
// The error never includes the connection string, which carries the password.
func migrationURL(databaseURL string) (string, error) {
	parsed, err := url.Parse(databaseURL)
	if err != nil {
		// err is discarded on purpose, against the usual %w convention:
		// url.Parse quotes the input it could not parse, so wrapping it here
		// would put the connection string, and the password in it, into the
		// error. Do not add %w back.
		return "", fmt.Errorf("database url is not a valid URL")
	}

	switch parsed.Scheme {
	case "postgres", "postgresql":
		parsed.Scheme = "pgx5"
	case "pgx5":
		// Already the driver's scheme.
	default:
		return "", fmt.Errorf("database url scheme %q is not supported; use postgres://", parsed.Scheme)
	}

	return parsed.String(), nil
}
