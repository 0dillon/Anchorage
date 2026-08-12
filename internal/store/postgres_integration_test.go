//go:build postgres_integration

// Run with a live database:
//
//	docker compose -f deploy/docker-compose.yml up -d postgres
//	SEP10_TEST_DATABASE_URL=postgres://anchorage:anchorage@localhost:5432/anchorage?sslmode=disable \
//	  go test -tags postgres_integration ./internal/store/ -v
package store

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/stretchr/testify/require"
)

func openTestStore(t *testing.T) *Postgres {
	t.Helper()

	dsn := os.Getenv("SEP10_TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("SEP10_TEST_DATABASE_URL is not set")
	}

	p, err := Open(context.Background(), dsn)
	require.NoError(t, err)
	t.Cleanup(p.Close)

	require.NoError(t, p.Migrate())

	// Each test starts from an empty table.
	_, err = p.pool.Exec(context.Background(), "TRUNCATE challenges, sessions")
	require.NoError(t, err)

	return p
}

func testChallenge(nonce string, now time.Time) ChallengeRecord {
	return ChallengeRecord{
		Nonce:        nonce,
		Account:      "GBXHUHG5FGYLPD6RHL2MKWMP572O6KUXCZXDZJXS4T57ZTMAKBN7DWXN",
		HomeDomain:   "example.com",
		ClientDomain: "wallet.example.org",
		IssuedAt:     now,
		ExpiresAt:    now.Add(5 * time.Minute),
	}
}

func TestConsumeChallengeSucceedsOnce(t *testing.T) {
	p := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, p.RecordChallenge(ctx, testChallenge("nonce-1", now)))

	got, err := p.ConsumeChallenge(ctx, "nonce-1", now)
	require.NoError(t, err)
	require.Equal(t, "example.com", got.HomeDomain)
	require.Equal(t, "wallet.example.org", got.ClientDomain)

	// The second use is the replay, and it must fail.
	_, err = p.ConsumeChallenge(ctx, "nonce-1", now)
	require.ErrorIs(t, err, auth.ErrChallengeConsumed)
}

func TestConsumeChallengeRejectsUnknownNonce(t *testing.T) {
	p := openTestStore(t)

	_, err := p.ConsumeChallenge(context.Background(), "never-issued", time.Now().UTC())
	require.ErrorIs(t, err, auth.ErrChallengeUnknown)
}

func TestConsumeChallengeRejectsExpired(t *testing.T) {
	p := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, p.RecordChallenge(ctx, testChallenge("nonce-2", now)))

	_, err := p.ConsumeChallenge(ctx, "nonce-2", now.Add(10*time.Minute))
	require.ErrorIs(t, err, auth.ErrChallengeExpired)
}

// Only one of many concurrent consumers can win. This is the property the
// single-statement update exists for.
func TestConsumeChallengeIsAtomic(t *testing.T) {
	p := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, p.RecordChallenge(ctx, testChallenge("nonce-3", now)))

	const racers = 8
	results := make(chan error, racers)
	start := make(chan struct{})

	for range racers {
		go func() {
			<-start
			_, err := p.ConsumeChallenge(ctx, "nonce-3", now)
			results <- err
		}()
	}
	close(start)

	succeeded := 0
	for range racers {
		if err := <-results; err == nil {
			succeeded++
		}
	}
	require.Equal(t, 1, succeeded)
}

func TestRecordChallengeRejectsDuplicateNonce(t *testing.T) {
	p := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, p.RecordChallenge(ctx, testChallenge("nonce-4", now)))
	require.Error(t, p.RecordChallenge(ctx, testChallenge("nonce-4", now)))
}

func TestDeleteExpiredChallenges(t *testing.T) {
	p := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	require.NoError(t, p.RecordChallenge(ctx, testChallenge("old", now.Add(-time.Hour))))
	require.NoError(t, p.RecordChallenge(ctx, testChallenge("new", now)))

	deleted, err := p.DeleteExpiredChallenges(ctx, now)
	require.NoError(t, err)
	require.Equal(t, int64(1), deleted)

	// The live one survived.
	_, err = p.ConsumeChallenge(ctx, "new", now)
	require.NoError(t, err)
}

func TestRecordSession(t *testing.T) {
	p := openTestStore(t)
	ctx := context.Background()
	now := time.Now().UTC()

	rec := SessionRecord{
		JTI:        "abc123",
		Account:    "GBXHUHG5FGYLPD6RHL2MKWMP572O6KUXCZXDZJXS4T57ZTMAKBN7DWXN",
		HomeDomain: "example.com",
		IssuedAt:   now,
		ExpiresAt:  now.Add(24 * time.Hour),
	}
	require.NoError(t, p.RecordSession(ctx, rec))
	// Sessions are the audit trail, so a duplicate jti is a bug, not a retry.
	require.Error(t, p.RecordSession(ctx, rec))
}
