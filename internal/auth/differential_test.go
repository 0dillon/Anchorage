package auth

import (
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stretchr/testify/require"
)

// TestReaderMatchesSDK pins our reader to txnbuild.ReadChallengeTx on every
// challenge shape both handle, which is all of them except client_domain.
//
// Our reader exists only because the SDK rejects the client_domain operation.
// Everywhere else it must agree with upstream exactly. If a future SDK release
// changes a rule, this test fails and someone decides deliberately whether to
// follow, rather than the two readers drifting apart unnoticed.
func TestReaderMatchesSDK(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(p *txnbuild.TransactionParams)
		signers []*keypair.Full
	}{
		{"valid", func(p *txnbuild.TransactionParams) {}, []*keypair.Full{serverKP}},
		{
			"valid with memo",
			func(p *txnbuild.TransactionParams) { p.Memo = txnbuild.MemoID(42) },
			[]*keypair.Full{serverKP},
		},
		{
			"valid with a client signature too",
			func(p *txnbuild.TransactionParams) {},
			[]*keypair.Full{serverKP, clientKP},
		},
		{"unsigned", func(p *txnbuild.TransactionParams) {}, nil},
		{"signed by the wrong key", func(p *txnbuild.TransactionParams) {}, []*keypair.Full{otherKP}},
		{
			"wrong transaction source",
			func(p *txnbuild.TransactionParams) {
				p.SourceAccount = &txnbuild.SimpleAccount{AccountID: otherKP.Address(), Sequence: 0}
			},
			[]*keypair.Full{otherKP},
		},
		{
			"non-zero sequence",
			func(p *txnbuild.TransactionParams) {
				p.SourceAccount = &txnbuild.SimpleAccount{AccountID: serverKP.Address(), Sequence: 3}
			},
			[]*keypair.Full{serverKP},
		},
		{
			"expired",
			func(p *txnbuild.TransactionParams) {
				past := time.Now().UTC().Add(-2 * time.Hour)
				p.Preconditions.TimeBounds = txnbuild.NewTimebounds(past.Unix(), past.Add(time.Minute).Unix())
			},
			[]*keypair.Full{serverKP},
		},
		{
			"not yet valid",
			func(p *txnbuild.TransactionParams) {
				future := time.Now().UTC().Add(2 * time.Hour)
				p.Preconditions.TimeBounds = txnbuild.NewTimebounds(future.Unix(), future.Add(time.Minute).Unix())
			},
			[]*keypair.Full{serverKP},
		},
		{
			"infinite timebounds",
			func(p *txnbuild.TransactionParams) {
				p.Preconditions.TimeBounds = txnbuild.NewInfiniteTimeout()
			},
			[]*keypair.Full{serverKP},
		},
		{
			"unmatched home domain",
			func(p *txnbuild.TransactionParams) {
				p.Operations[0].(*txnbuild.ManageData).Name = "attacker.example.net auth"
			},
			[]*keypair.Full{serverKP},
		},
		{
			"second configured home domain",
			func(p *txnbuild.TransactionParams) {
				p.Operations[0].(*txnbuild.ManageData).Name = "second.example.com auth"
			},
			[]*keypair.Full{serverKP},
		},
		{
			"nonce too short",
			func(p *txnbuild.TransactionParams) {
				p.Operations[0].(*txnbuild.ManageData).Value = []byte("short")
			},
			[]*keypair.Full{serverKP},
		},
		{
			"nonce not base64",
			func(p *txnbuild.TransactionParams) {
				bad := make([]byte, 64)
				for i := range bad {
					bad[i] = '!'
				}
				p.Operations[0].(*txnbuild.ManageData).Value = bad
			},
			[]*keypair.Full{serverKP},
		},
		{
			"web_auth_domain mismatch",
			func(p *txnbuild.TransactionParams) {
				p.Operations[1].(*txnbuild.ManageData).Value = []byte("attacker.example.net")
			},
			[]*keypair.Full{serverKP},
		},
		{
			"web_auth_domain sourced at the client",
			func(p *txnbuild.TransactionParams) {
				p.Operations[1].(*txnbuild.ManageData).SourceAccount = clientKP.Address()
			},
			[]*keypair.Full{serverKP},
		},
		{
			"unknown op sourced at the server",
			func(p *txnbuild.TransactionParams) {
				p.Operations = append(p.Operations, &txnbuild.ManageData{
					SourceAccount: serverKP.Address(),
					Name:          "extra",
					Value:         []byte("x"),
				})
			},
			[]*keypair.Full{serverKP},
		},
		{
			"unknown op sourced elsewhere",
			func(p *txnbuild.TransactionParams) {
				p.Operations = append(p.Operations, &txnbuild.ManageData{
					SourceAccount: otherKP.Address(),
					Name:          "extra",
					Value:         []byte("x"),
				})
			},
			[]*keypair.Full{serverKP},
		},
		{
			"memo with a text type",
			func(p *txnbuild.TransactionParams) { p.Memo = txnbuild.MemoText("hi") },
			[]*keypair.Full{serverKP},
		},
		{
			"web_auth_domain operation omitted",
			func(p *txnbuild.TransactionParams) {
				p.Operations = p.Operations[:1]
			},
			[]*keypair.Full{serverKP},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			params := defaultParams()
			tt.mutate(&params)
			challenge := buildTx(t, params, tt.signers...)

			ours, ourErr := ReadChallenge(
				challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())

			_, sdkAccount, sdkHomeDomain, sdkMemo, sdkErr := txnbuild.ReadChallengeTx(
				challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())

			if sdkErr != nil {
				require.Errorf(t, ourErr,
					"SDK rejected this challenge (%v) but our reader accepted it", sdkErr)
				return
			}

			require.NoErrorf(t, ourErr,
				"SDK accepted this challenge but our reader rejected it")
			require.Equal(t, sdkAccount, ours.ClientAccountID)
			require.Equal(t, sdkHomeDomain, ours.HomeDomain)

			if sdkMemo == nil {
				require.Nil(t, ours.Memo)
			} else {
				require.NotNil(t, ours.Memo)
				require.Equal(t, *sdkMemo, *ours.Memo)
			}
		})
	}
}

// The one shape where disagreement is the point.
func TestReaderDivergesOnlyOnClientDomain(t *testing.T) {
	params := defaultParams()
	params.Operations = append(params.Operations, clientDomainOp())
	challenge := buildTx(t, params, serverKP)

	_, ourErr := ReadChallenge(challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.NoError(t, ourErr, "our reader must accept a spec-compliant client_domain challenge")

	_, _, _, _, sdkErr := txnbuild.ReadChallengeTx(
		challenge, serverKP.Address(), testNetwork, testWebAuthDomain, homeDomains())
	require.Error(t, sdkErr, "if the SDK now accepts client_domain, our reader may no longer be needed")
}
