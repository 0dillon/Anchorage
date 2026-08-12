package httpapi

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/0dillon/Anchorage/internal/store"
	"github.com/0dillon/Anchorage/internal/token"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stretchr/testify/require"
)

const (
	testNetwork       = network.TestNetworkPassphrase
	testWebAuthDomain = "auth.example.com"
	testHomeDomain    = "example.com"
	testClientDomain  = "wallet.example.org"
)

// Keypairs are derived from fixed raw seeds, never pasted: a strkey carries a
// checksum and a hand-written one does not parse.
var (
	serverKP       = mustKeypair(1)
	clientKP       = mustKeypair(2)
	clientDomainKP = mustKeypair(3)
)

func mustKeypair(fill byte) *keypair.Full {
	var raw [32]byte
	for i := range raw {
		raw[i] = fill
	}
	kp, err := keypair.FromRawSeed(raw)
	if err != nil {
		panic(err)
	}
	return kp
}

// fakeResolver stands in for the client domain resolver. It never touches the
// network.
type fakeResolver struct {
	key string
	err error
}

func (f fakeResolver) Resolve(context.Context, string) (string, error) {
	if f.err != nil {
		return "", f.err
	}
	return f.key, nil
}

// fakeStore mimics the Postgres store, including the part that matters: a
// nonce can be consumed exactly once, and consumption is guarded by a lock so
// two concurrent consumers cannot both win.
type fakeStore struct {
	mu sync.Mutex

	challenges map[string]store.ChallengeRecord
	consumed   map[string]bool
	sessions   []store.SessionRecord

	// recordErr and consumeErr force an infrastructure failure, which must be
	// reported as 503 and never as a bad signature.
	recordErr  error
	consumeErr error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		challenges: make(map[string]store.ChallengeRecord),
		consumed:   make(map[string]bool),
	}
}

func (f *fakeStore) RecordChallenge(_ context.Context, rec store.ChallengeRecord) error {
	if f.recordErr != nil {
		return f.recordErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	f.challenges[rec.Nonce] = rec
	return nil
}

func (f *fakeStore) ConsumeChallenge(_ context.Context, nonce string, now time.Time) (*store.ConsumedChallenge, error) {
	if f.consumeErr != nil {
		return nil, f.consumeErr
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	rec, ok := f.challenges[nonce]
	if !ok {
		return nil, auth.ErrChallengeUnknown
	}
	if f.consumed[nonce] {
		return nil, auth.ErrChallengeConsumed
	}
	if !rec.ExpiresAt.After(now) {
		return nil, auth.ErrChallengeExpired
	}

	f.consumed[nonce] = true
	return &store.ConsumedChallenge{
		Account:      rec.Account,
		HomeDomain:   rec.HomeDomain,
		ClientDomain: rec.ClientDomain,
	}, nil
}

func (f *fakeStore) RecordSession(_ context.Context, rec store.SessionRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.sessions = append(f.sessions, rec)
	return nil
}

// testIssuer builds a challenge issuer wired to the fake resolver.
func testIssuer(t *testing.T, resolver auth.ClientDomainResolver) *auth.Issuer {
	t.Helper()

	issuer, err := auth.NewIssuer(auth.IssuerConfig{
		SigningSecret:     serverKP.Seed(),
		NetworkPassphrase: testNetwork,
		WebAuthDomain:     testWebAuthDomain,
		HomeDomains:       []string{testHomeDomain},
		ChallengeTimeout:  5 * time.Minute,
		Resolver:          resolver,
	})
	require.NoError(t, err)
	return issuer
}

// newTestDeps returns a complete Deps and the fake store behind it. Tests
// override individual fields before calling NewRouter.
func newTestDeps(t *testing.T) (Deps, *fakeStore) {
	t.Helper()

	tokens, err := token.NewIssuer(token.IssuerConfig{
		Secret:   []byte("0123456789abcdef0123456789abcdef"),
		Issuer:   "https://auth.example.com",
		Lifetime: time.Hour,
	})
	require.NoError(t, err)

	fake := newFakeStore()

	return Deps{
		Logger:     discardLogger(),
		Issuer:     testIssuer(t, fakeResolver{key: clientDomainKP.Address()}),
		Tokens:     tokens,
		Challenges: fake,
		Health:     fakePinger{},
		Accounts: fakeAccounts{account: &auth.Account{
			Signers:      map[string]int32{clientKP.Address(): 1},
			MedThreshold: 1,
		}},
		NetworkPassphrase: testNetwork,
		WebAuthDomain:     testWebAuthDomain,
		HomeDomains:       []string{testHomeDomain},
		TOMLPath:          writeTOML(t, "VERSION = \"2.0.0\"\nSIGNING_KEY = \"${SIGNING_KEY}\"\n"),
		SigningPublicKey:  serverKP.Address(),
	}, fake
}

// fakeAccounts stands in for Horizon.
type fakeAccounts struct {
	account *auth.Account
	err     error
}

func (f fakeAccounts) Account(context.Context, string) (*auth.Account, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.account, nil
}
