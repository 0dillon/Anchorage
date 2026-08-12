package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stretchr/testify/require"
)

type fakeAccounts struct {
	account *Account
	err     error
}

func (f fakeAccounts) Account(context.Context, string) (*Account, error) {
	if f.err != nil {
		return nil, f.err
	}
	return f.account, nil
}

// readSigned builds a challenge, signs it, and reads it back.
func readSigned(t *testing.T, params txnbuild.TransactionParams, signers ...*keypair.Full) *Challenge {
	t.Helper()

	challenge, err := ReadChallenge(
		buildTx(t, params, signers...),
		serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)
	return challenge
}

func TestVerifyClientAccountDoesNotExist(t *testing.T) {
	challenge := readSigned(t, defaultParams(), serverKP, clientKP)

	found, err := VerifyClient(context.Background(), challenge, testNetwork,
		fakeAccounts{err: ErrAccountNotFound})

	require.NoError(t, err)
	require.Equal(t, []string{clientKP.Address()}, found)
}

func TestVerifyClientAccountDoesNotExistWrongSigner(t *testing.T) {
	// Signed by a key that is not the account's master key.
	challenge := readSigned(t, defaultParams(), serverKP, otherKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork,
		fakeAccounts{err: ErrAccountNotFound})

	require.ErrorIs(t, err, ErrSignatureUnrecognized)
}

func TestVerifyClientThresholdMet(t *testing.T) {
	challenge := readSigned(t, defaultParams(), serverKP, clientKP, extraKP)

	found, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers: map[string]int32{
				clientKP.Address(): 1,
				extraKP.Address():  1,
			},
			MedThreshold: 2,
		},
	})

	require.NoError(t, err)
	require.ElementsMatch(t, []string{clientKP.Address(), extraKP.Address()}, found)
}

func TestVerifyClientThresholdNotMet(t *testing.T) {
	challenge := readSigned(t, defaultParams(), serverKP, clientKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers: map[string]int32{
				clientKP.Address(): 1,
				extraKP.Address():  1,
			},
			MedThreshold: 2,
		},
	})

	require.ErrorIs(t, err, ErrThresholdNotMet)
}

func TestVerifyClientNoClientSignature(t *testing.T) {
	challenge := readSigned(t, defaultParams(), serverKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers:      map[string]int32{clientKP.Address(): 1},
			MedThreshold: 1,
		},
	})

	require.ErrorIs(t, err, ErrSignatureUnrecognized)
}

func TestVerifyClientUnrecognisedSignature(t *testing.T) {
	// otherKP is not a signer on the account, so its signature is unaccounted for.
	challenge := readSigned(t, defaultParams(), serverKP, clientKP, otherKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers:      map[string]int32{clientKP.Address(): 5},
			MedThreshold: 1,
		},
	})

	require.ErrorIs(t, err, ErrSignatureUnrecognized)
}

func TestVerifyClientLookupFailure(t *testing.T) {
	challenge := readSigned(t, defaultParams(), serverKP, clientKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork,
		fakeAccounts{err: errors.New("horizon timed out")})

	require.ErrorIs(t, err, ErrAccountLookupFailed)
	// An outage must never look like a bad signature.
	require.NotErrorIs(t, err, ErrSignatureUnrecognized)
}

func clientDomainParams() txnbuild.TransactionParams {
	params := defaultParams()
	params.Operations = append(params.Operations, clientDomainOp())
	return params
}

func TestVerifyClientDomainSigned(t *testing.T) {
	challenge := readSigned(t, clientDomainParams(), serverKP, clientKP, clientDomainKP)

	found, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers:      map[string]int32{clientKP.Address(): 1},
			MedThreshold: 1,
		},
	})

	require.NoError(t, err)
	require.Contains(t, found, clientDomainKP.Address())
}

func TestVerifyClientDomainNotSigned(t *testing.T) {
	// The challenge names a client domain, but the client domain did not sign.
	challenge := readSigned(t, clientDomainParams(), serverKP, clientKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers:      map[string]int32{clientKP.Address(): 1},
			MedThreshold: 1,
		},
	})

	require.ErrorIs(t, err, ErrClientDomainUnverified)
}

// TestClientDomainWeightDoesNotSatisfyThreshold is the guard on the most
// dangerous line in the project. If the exclusion in accountSignerWeight is
// removed, the sum below becomes 3, verification succeeds, and this test fails.
//
// The account contributes weight 1 against a threshold of 2. The client domain
// key carries weight 2 in the summary, but that weight is not the account's to
// spend: a client domain proves a wallet took part, never that the account
// authorised anything. Counting it would let any client domain authenticate
// for any account.
func TestClientDomainWeightDoesNotSatisfyThreshold(t *testing.T) {
	challenge := readSigned(t, clientDomainParams(), serverKP, clientKP, clientDomainKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers: map[string]int32{
				clientKP.Address():       1,
				clientDomainKP.Address(): 2,
			},
			MedThreshold: 2,
		},
	})

	require.ErrorIs(t, err, ErrThresholdNotMet)
}

// The control for the test above: the same shape, but the account itself
// carries enough weight. This must pass, so the test above is failing for the
// right reason rather than because client domain challenges never verify.
func TestAccountWeightAloneSatisfiesThreshold(t *testing.T) {
	challenge := readSigned(t, clientDomainParams(), serverKP, clientKP, clientDomainKP)

	found, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers: map[string]int32{
				clientKP.Address():       2,
				clientDomainKP.Address(): 2,
			},
			MedThreshold: 2,
		},
	})

	require.NoError(t, err)
	require.Contains(t, found, clientKP.Address())
}

// A challenge signed by the server and the client domain alone must not
// authenticate the account. The client domain proves the wallet took part; it
// never proves the account authorised anything. A Stellar account's thresholds
// default to 0, so a zero medium threshold is the ordinary case, not an
// exotic one, and a weight of 0 must not clear it.
func TestVerifyClientDomainAloneDoesNotAuthenticate(t *testing.T) {
	challenge := readSigned(t, clientDomainParams(), serverKP, clientDomainKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers:      map[string]int32{clientKP.Address(): 1},
			MedThreshold: 0,
		},
	})

	require.ErrorIs(t, err, ErrSignatureUnrecognized)
}

// The same shape on the account-does-not-exist path, which returns without ever
// reaching the threshold comparison.
func TestVerifyClientDomainAloneDoesNotAuthenticateMissingAccount(t *testing.T) {
	challenge := readSigned(t, clientDomainParams(), serverKP, clientDomainKP)

	_, err := VerifyClient(context.Background(), challenge, testNetwork,
		fakeAccounts{err: ErrAccountNotFound})

	require.ErrorIs(t, err, ErrSignatureUnrecognized)
}

// The control: a zero medium threshold with a real signature from the account
// still authenticates. Without this, the tests above could pass because client
// domain challenges never verify at all.
func TestVerifyClientZeroThresholdWithAccountSignature(t *testing.T) {
	challenge := readSigned(t, clientDomainParams(), serverKP, clientKP, clientDomainKP)

	found, err := VerifyClient(context.Background(), challenge, testNetwork, fakeAccounts{
		account: &Account{
			Signers:      map[string]int32{clientKP.Address(): 1},
			MedThreshold: 0,
		},
	})

	require.NoError(t, err)
	require.Contains(t, found, clientKP.Address())
}

func TestAccountSignerWeightExcludesClientDomain(t *testing.T) {
	summary := map[string]int32{
		clientKP.Address():       1,
		clientDomainKP.Address(): 7,
	}
	found := []string{clientKP.Address(), clientDomainKP.Address()}

	require.Equal(t, int32(1), accountSignerWeight(found, summary, clientDomainKP.Address()))
	// With no client domain in play, every matched signer counts.
	require.Equal(t, int32(8), accountSignerWeight(found, summary, ""))
}
