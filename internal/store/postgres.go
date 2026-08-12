package store

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Postgres is the Postgres-backed store.
type Postgres struct {
	pool        *pgxpool.Pool
	databaseURL string
}

// Open connects to the database and verifies the connection.
func Open(ctx context.Context, databaseURL string) (*Postgres, error) {
	pool, err := pgxpool.New(ctx, databaseURL)
	if err != nil {
		// The connection string carries the password, so it is not included.
		return nil, fmt.Errorf("connecting to the database failed")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("database ping failed: %w", err)
	}
	return &Postgres{pool: pool, databaseURL: databaseURL}, nil
}

// Close releases the connection pool.
func (p *Postgres) Close() {
	p.pool.Close()
}

// Ping reports whether the database is reachable. The health endpoint uses it.
func (p *Postgres) Ping(ctx context.Context) error {
	if err := p.pool.Ping(ctx); err != nil {
		return fmt.Errorf("database ping failed: %w", err)
	}
	return nil
}

// Migrate applies the embedded migrations. Running it when the schema is
// already current is not an error.
func (p *Postgres) Migrate() error {
	source, err := iofs.New(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("reading embedded migrations: %w", err)
	}

	dsn, err := migrationURL(p.databaseURL)
	if err != nil {
		return err
	}

	m, err := migrate.NewWithSourceInstance("iofs", source, dsn)
	if err != nil {
		return fmt.Errorf("preparing migrations failed")
	}
	defer m.Close()

	if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("applying migrations: %w", err)
	}
	return nil
}

// RecordChallenge stores a newly issued challenge. The nonce is the primary
// key, so a repeat insert fails rather than overwriting the original.
func (p *Postgres) RecordChallenge(ctx context.Context, rec ChallengeRecord) error {
	const query = `
		INSERT INTO challenges (nonce, account, home_domain, client_domain, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)`

	_, err := p.pool.Exec(ctx, query,
		rec.Nonce, rec.Account, rec.HomeDomain,
		nullable(rec.ClientDomain), rec.IssuedAt, rec.ExpiresAt)
	if err != nil {
		return fmt.Errorf("recording challenge: %w", err)
	}
	return nil
}

// ConsumeChallenge marks a challenge used and returns what it was issued for.
//
// The update is one statement. It matches only a row that is unconsumed and
// unexpired, so two concurrent callers cannot both succeed: the second finds
// consumed_at already set and matches nothing. Reading the row first and
// writing it after would let both through.
func (p *Postgres) ConsumeChallenge(ctx context.Context, nonce string, now time.Time) (*ConsumedChallenge, error) {
	// expires_at is the signed transaction's own MaxTime, and a challenge is
	// consumable up to and including that instant, matching internal/auth/read.go
	// and the SDK. Hence expires_at >= $2, not >.
	const consume = `
		UPDATE challenges SET consumed_at = $2
		WHERE nonce = $1 AND consumed_at IS NULL AND expires_at >= $2
		RETURNING account, home_domain, client_domain`

	var (
		out          ConsumedChallenge
		clientDomain *string
	)
	err := p.pool.QueryRow(ctx, consume, nonce, now).
		Scan(&out.Account, &out.HomeDomain, &clientDomain)
	if err == nil {
		if clientDomain != nil {
			out.ClientDomain = *clientDomain
		}
		return &out, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return nil, fmt.Errorf("consuming challenge: %w", err)
	}

	// Nothing matched. Only now is a second query worth running, to say which
	// of the three reasons it was.
	return nil, p.classifyFailure(ctx, nonce, now)
}

// classifyFailure tells an unknown nonce from a consumed one from an expired
// one. It runs only after the update matched nothing, so it never races with a
// successful consumption.
func (p *Postgres) classifyFailure(ctx context.Context, nonce string, now time.Time) error {
	const inspect = `SELECT consumed_at, expires_at FROM challenges WHERE nonce = $1`

	var (
		consumedAt *time.Time
		expiresAt  time.Time
	)
	err := p.pool.QueryRow(ctx, inspect, nonce).Scan(&consumedAt, &expiresAt)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return fmt.Errorf("%w", auth.ErrChallengeUnknown)
	case err != nil:
		return fmt.Errorf("inspecting challenge: %w", err)
	case consumedAt != nil:
		return fmt.Errorf("%w", auth.ErrChallengeConsumed)
	case expiresAt.Before(now):
		return fmt.Errorf("%w", auth.ErrChallengeExpired)
	default:
		// The row is live and unconsumed, so the update should have matched.
		// Reaching here means another caller consumed it between the two
		// queries, which is still a replay from this caller's point of view.
		return fmt.Errorf("%w", auth.ErrChallengeConsumed)
	}
}

// RecordSession stores an issued token. Sessions are never deleted.
func (p *Postgres) RecordSession(ctx context.Context, rec SessionRecord) error {
	const query = `
		INSERT INTO sessions (jti, account, memo, home_domain, client_domain, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`

	_, err := p.pool.Exec(ctx, query,
		rec.JTI, rec.Account, nullable(rec.Memo), rec.HomeDomain,
		nullable(rec.ClientDomain), rec.IssuedAt, rec.ExpiresAt)
	if err != nil {
		return fmt.Errorf("recording session: %w", err)
	}
	return nil
}

// DeleteExpiredChallenges removes challenge rows that expired before the given
// time and returns how many were removed.
func (p *Postgres) DeleteExpiredChallenges(ctx context.Context, before time.Time) (int64, error) {
	const query = `DELETE FROM challenges WHERE expires_at < $1`

	tag, err := p.pool.Exec(ctx, query, before)
	if err != nil {
		return 0, fmt.Errorf("deleting expired challenges: %w", err)
	}
	return tag.RowsAffected(), nil
}

// CleanupExpiredChallenges deletes expired challenges on a loop until the
// context is cancelled. It blocks, so callers run it in its own goroutine.
//
// A failed sweep is logged and the loop continues: the next tick retries, and
// a stale challenge row is harmless because expiry is enforced by the consume
// statement, not by this loop.
func (p *Postgres) CleanupExpiredChallenges(ctx context.Context, interval time.Duration, logger *slog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			deleted, err := p.DeleteExpiredChallenges(ctx, time.Now().UTC())
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				logger.Error("challenge cleanup failed", "error", err)
				continue
			}
			if deleted > 0 {
				logger.Info("deleted expired challenges", "count", deleted)
			}
		}
	}
}

// nullable maps an empty string to SQL NULL, so an absent client domain is
// stored as NULL rather than as an empty string.
func nullable(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
