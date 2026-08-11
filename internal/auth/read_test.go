package auth

import (
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stretchr/testify/require"
)

func TestReadChallengeValid(t *testing.T) {
	challenge := buildTx(t, defaultParams(), serverKP)

	got, err := ReadChallenge(challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)

	require.Equal(t, clientKP.Address(), got.ClientAccountID)
	require.Equal(t, testHomeDomain, got.HomeDomain)
	require.Equal(t, testNonce(), got.Nonce)
	require.Nil(t, got.Memo)
	require.Empty(t, got.ClientDomain)
	require.Empty(t, got.ClientDomainKey)
}

// The case the SDK cannot handle. This is why internal/auth has its own reader.
func TestReadChallengeWithClientDomain(t *testing.T) {
	params := defaultParams()
	params.Operations = append(params.Operations, clientDomainOp())

	challenge := buildTx(t, params, serverKP)

	got, err := ReadChallenge(challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)
	require.Equal(t, testClientDomain, got.ClientDomain)
	require.Equal(t, clientDomainKP.Address(), got.ClientDomainKey)

	// And confirm the SDK really does reject it, so this test documents the
	// upstream behaviour rather than asserting it from memory.
	_, _, _, _, sdkErr := txnbuild.ReadChallengeTx(
		challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.Error(t, sdkErr)
	require.Contains(t, sdkErr.Error(), "subsequent operations are unrecognized")
}

func TestReadChallengeMemo(t *testing.T) {
	params := defaultParams()
	params.Memo = txnbuild.MemoID(1234)

	challenge := buildTx(t, params, serverKP)

	got, err := ReadChallenge(challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, err)
	require.NotNil(t, got.Memo)
	require.Equal(t, txnbuild.MemoID(1234), *got.Memo)
}

func TestReadChallengeRejections(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(p *txnbuild.TransactionParams)
		signers []*keypair.Full
		wantErr error
	}{
		{
			name:    "unsigned by server",
			mutate:  func(p *txnbuild.TransactionParams) {},
			signers: nil,
			wantErr: ErrChallengeMalformed,
		},
		{
			name:    "signed by the wrong key",
			mutate:  func(p *txnbuild.TransactionParams) {},
			signers: []*keypair.Full{otherKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "wrong transaction source",
			mutate: func(p *txnbuild.TransactionParams) {
				p.SourceAccount = &txnbuild.SimpleAccount{AccountID: otherKP.Address(), Sequence: 0}
			},
			signers: []*keypair.Full{otherKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "non-zero sequence",
			mutate: func(p *txnbuild.TransactionParams) {
				p.SourceAccount = &txnbuild.SimpleAccount{AccountID: serverKP.Address(), Sequence: 9}
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "expired timebounds",
			mutate: func(p *txnbuild.TransactionParams) {
				past := time.Now().UTC().Add(-time.Hour)
				p.Preconditions.TimeBounds = txnbuild.NewTimebounds(past.Unix(), past.Add(time.Minute).Unix())
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeExpired,
		},
		{
			name: "unmatched home domain",
			mutate: func(p *txnbuild.TransactionParams) {
				p.Operations[0].(*txnbuild.ManageData).Name = "attacker.example.net auth"
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrUnknownHomeDomain,
		},
		{
			name: "nonce wrong length",
			mutate: func(p *txnbuild.TransactionParams) {
				p.Operations[0].(*txnbuild.ManageData).Value = []byte("too short")
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "nonce not base64",
			mutate: func(p *txnbuild.TransactionParams) {
				bad := make([]byte, 64)
				for i := range bad {
					bad[i] = '!'
				}
				p.Operations[0].(*txnbuild.ManageData).Value = bad
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "web_auth_domain value mismatch",
			mutate: func(p *txnbuild.TransactionParams) {
				p.Operations[1].(*txnbuild.ManageData).Value = []byte("attacker.example.net")
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "web_auth_domain sourced at the client",
			mutate: func(p *txnbuild.TransactionParams) {
				p.Operations[1].(*txnbuild.ManageData).SourceAccount = clientKP.Address()
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "unknown operation not sourced at the server",
			mutate: func(p *txnbuild.TransactionParams) {
				p.Operations = append(p.Operations, &txnbuild.ManageData{
					SourceAccount: otherKP.Address(),
					Name:          "something_else",
					Value:         []byte("x"),
				})
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "client_domain sourced at a muxed account",
			mutate: func(p *txnbuild.TransactionParams) {
				op := clientDomainOp()
				// A muxed address is not a valid signing key.
				op.SourceAccount = "MA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVAAAAAAAAAAAAAJLK"
				p.Operations = append(p.Operations, op)
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "memo with a non-ID type",
			mutate: func(p *txnbuild.TransactionParams) {
				p.Memo = txnbuild.MemoText("hello")
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "two client_domain operations",
			mutate: func(p *txnbuild.TransactionParams) {
				p.Operations = append(p.Operations, clientDomainOp(), clientDomainOp())
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "two web_auth_domain operations",
			mutate: func(p *txnbuild.TransactionParams) {
				p.Operations = append(p.Operations, &txnbuild.ManageData{
					SourceAccount: serverKP.Address(),
					Name:          "web_auth_domain",
					Value:         []byte(testWebAuthDomain),
				})
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
		{
			name: "client_domain sourced at the server",
			mutate: func(p *txnbuild.TransactionParams) {
				op := clientDomainOp()
				op.SourceAccount = serverKP.Address()
				p.Operations = append(p.Operations, op)
			},
			signers: []*keypair.Full{serverKP},
			wantErr: ErrChallengeMalformed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := defaultParams()
			tt.mutate(&params)

			challenge := buildTx(t, params, tt.signers...)

			_, err := ReadChallenge(challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

func TestReadChallengeRejectsGarbageXDR(t *testing.T) {
	_, err := ReadChallenge("not base64 xdr", serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.ErrorIs(t, err, ErrChallengeMalformed)
}
