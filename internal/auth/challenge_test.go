package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stellar/go-stellar-sdk/xdr"
	"github.com/stretchr/testify/require"
)

type fakeResolver struct {
	key    string
	err    error
	calls  int
	domain string
}

func (f *fakeResolver) Resolve(_ context.Context, domain string) (string, error) {
	f.calls++
	f.domain = domain
	if f.err != nil {
		return "", f.err
	}
	return f.key, nil
}

func testIssuer(t *testing.T, resolver ClientDomainResolver, required bool) *Issuer {
	t.Helper()

	issuer, err := NewIssuer(IssuerConfig{
		SigningSecret:        serverKP.Seed(),
		NetworkPassphrase:    testNetwork,
		WebAuthDomain:        testWebAuthDomain,
		HomeDomains:          homeDomains(),
		ChallengeTimeout:     5 * time.Minute,
		ClientDomainRequired: required,
		Resolver:             resolver,
	})
	require.NoError(t, err)
	return issuer
}

func TestIssueRoundTrips(t *testing.T) {
	issuer := testIssuer(t, &fakeResolver{}, false)

	issued, err := issuer.Issue(context.Background(), IssueRequest{Account: clientKP.Address()})
	require.NoError(t, err)
	require.Equal(t, testNetwork, issued.NetworkPassphrase)
	require.Equal(t, clientKP.Address(), issued.Account)
	require.Equal(t, testHomeDomain, issued.HomeDomain)
	require.True(t, issued.ExpiresAt.After(time.Now()))

	// The challenge we issue must be one we can read back.
	read, err := ReadChallenge(issued.TransactionXDR, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)
	require.Equal(t, clientKP.Address(), read.ClientAccountID)
	require.Equal(t, issued.Nonce, read.Nonce)
	require.Empty(t, read.ClientDomain)
}

func TestIssueWithMemo(t *testing.T) {
	issuer := testIssuer(t, &fakeResolver{}, false)
	memo := uint64(9876)

	issued, err := issuer.Issue(context.Background(), IssueRequest{
		Account: clientKP.Address(),
		Memo:    &memo,
	})
	require.NoError(t, err)

	read, err := ReadChallenge(issued.TransactionXDR, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)
	require.NotNil(t, read.Memo)
	require.Equal(t, txnbuild.MemoID(9876), *read.Memo)
}

func TestIssueWithMuxedAccount(t *testing.T) {
	muxed, err := xdr.MuxedAccountFromAccountId(clientKP.Address(), 17)
	require.NoError(t, err)

	issuer := testIssuer(t, &fakeResolver{}, false)

	issued, err := issuer.Issue(context.Background(), IssueRequest{Account: muxed.Address()})
	require.NoError(t, err)

	read, err := ReadChallenge(issued.TransactionXDR, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)
	require.Equal(t, muxed.Address(), read.ClientAccountID)
}

func TestIssueRejectsMemoWithMuxedAccount(t *testing.T) {
	muxed, err := xdr.MuxedAccountFromAccountId(clientKP.Address(), 17)
	require.NoError(t, err)

	issuer := testIssuer(t, &fakeResolver{}, false)
	memo := uint64(1)

	_, err = issuer.Issue(context.Background(), IssueRequest{Account: muxed.Address(), Memo: &memo})
	require.ErrorIs(t, err, ErrMemoWithMuxed)
}

func TestIssueRejectsBadAccount(t *testing.T) {
	issuer := testIssuer(t, &fakeResolver{}, false)

	for _, account := range []string{"", "not-an-address", serverKP.Seed()} {
		_, err := issuer.Issue(context.Background(), IssueRequest{Account: account})
		require.ErrorIs(t, err, ErrInvalidAccount, "account %q", account)
	}
}

func TestIssueRejectsUnknownHomeDomain(t *testing.T) {
	issuer := testIssuer(t, &fakeResolver{}, false)

	_, err := issuer.Issue(context.Background(), IssueRequest{
		Account:    clientKP.Address(),
		HomeDomain: "attacker.example.net",
	})
	require.ErrorIs(t, err, ErrUnknownHomeDomain)
}

func TestIssueWithClientDomain(t *testing.T) {
	resolver := &fakeResolver{key: clientDomainKP.Address()}
	issuer := testIssuer(t, resolver, false)

	issued, err := issuer.Issue(context.Background(), IssueRequest{
		Account:      clientKP.Address(),
		ClientDomain: testClientDomain,
	})
	require.NoError(t, err)
	require.Equal(t, 1, resolver.calls)
	require.Equal(t, testClientDomain, resolver.domain)
	require.Equal(t, testClientDomain, issued.ClientDomain)

	read, err := ReadChallenge(issued.TransactionXDR, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)
	require.Equal(t, testClientDomain, read.ClientDomain)
	require.Equal(t, clientDomainKP.Address(), read.ClientDomainKey)

	// Re-signing after appending the operation must leave exactly one valid
	// server signature, not a stale one alongside it.
	require.Len(t, read.Tx.Signatures(), 1)
}

func TestIssueClientDomainResolutionFailure(t *testing.T) {
	resolver := &fakeResolver{err: errors.New("no SIGNING_KEY")}

	// Not required: a resolution failure is still fatal to a request that asked
	// for a client domain, because the caller asked for a guarantee we cannot
	// give.
	issuer := testIssuer(t, resolver, false)

	_, err := issuer.Issue(context.Background(), IssueRequest{
		Account:      clientKP.Address(),
		ClientDomain: testClientDomain,
	})
	require.ErrorIs(t, err, ErrClientDomainRejected)
}

func TestIssueClientDomainResolvesToEmptyKey(t *testing.T) {
	// A resolver that returns ("", nil) reports success but gives nothing to
	// bind the challenge to. That must be rejected, not silently downgraded to
	// a challenge without a client_domain operation.
	resolver := &fakeResolver{key: ""}

	issuer := testIssuer(t, resolver, false)

	_, err := issuer.Issue(context.Background(), IssueRequest{
		Account:      clientKP.Address(),
		ClientDomain: testClientDomain,
	})
	require.ErrorIs(t, err, ErrClientDomainRejected)
}

func TestIssueClientDomainRequiredButAbsent(t *testing.T) {
	issuer := testIssuer(t, &fakeResolver{key: clientDomainKP.Address()}, true)

	_, err := issuer.Issue(context.Background(), IssueRequest{Account: clientKP.Address()})
	require.ErrorIs(t, err, ErrClientDomainRequired)
}

func TestIssueSelectsRequestedHomeDomain(t *testing.T) {
	issuer := testIssuer(t, &fakeResolver{}, false)

	issued, err := issuer.Issue(context.Background(), IssueRequest{
		Account:    clientKP.Address(),
		HomeDomain: "second.example.com",
	})
	require.NoError(t, err)
	require.Equal(t, "second.example.com", issued.HomeDomain)

	read, err := ReadChallenge(issued.TransactionXDR, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)
	require.Equal(t, "second.example.com", read.HomeDomain)
}

func TestIssueNoncesDiffer(t *testing.T) {
	issuer := testIssuer(t, &fakeResolver{}, false)

	first, err := issuer.Issue(context.Background(), IssueRequest{Account: clientKP.Address()})
	require.NoError(t, err)
	second, err := issuer.Issue(context.Background(), IssueRequest{Account: clientKP.Address()})
	require.NoError(t, err)

	require.NotEqual(t, first.Nonce, second.Nonce)
}
