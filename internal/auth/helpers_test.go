package auth

import (
	"encoding/base64"
	"testing"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/network"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stretchr/testify/require"
)

const (
	testNetwork       = network.TestNetworkPassphrase
	testWebAuthDomain = "auth.example.com"
	testHomeDomain    = "example.com"
	testClientDomain  = "wallet.example.org"
)

// Keypairs are derived from fixed raw seeds so tests are reproducible without
// pasting strkey literals, which carry checksums and are easy to get wrong.
var (
	serverKP       = mustKeypair(1)
	clientKP       = mustKeypair(2)
	clientDomainKP = mustKeypair(3)
	otherKP        = mustKeypair(4)
	extraKP        = mustKeypair(5)
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

// testNonce is a valid SEP-10 nonce: 48 raw bytes, 64 base64 characters.
func testNonce() string {
	raw := make([]byte, 48)
	for i := range raw {
		raw[i] = byte(i)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

// homeDomains is the configured list every test reads against.
func homeDomains() []string {
	return []string{testHomeDomain, "second.example.com"}
}

// defaultParams returns a valid two-operation challenge. Tests mutate the
// result to build each malformed variant.
func defaultParams() txnbuild.TransactionParams {
	now := time.Now().UTC()
	return txnbuild.TransactionParams{
		SourceAccount:        &txnbuild.SimpleAccount{AccountID: serverKP.Address(), Sequence: 0},
		IncrementSequenceNum: false,
		Operations: []txnbuild.Operation{
			&txnbuild.ManageData{
				SourceAccount: clientKP.Address(),
				Name:          testHomeDomain + " auth",
				Value:         []byte(testNonce()),
			},
			&txnbuild.ManageData{
				SourceAccount: serverKP.Address(),
				Name:          "web_auth_domain",
				Value:         []byte(testWebAuthDomain),
			},
		},
		BaseFee: txnbuild.MinBaseFee,
		Preconditions: txnbuild.Preconditions{
			TimeBounds: txnbuild.NewTimebounds(now.Unix(), now.Add(5*time.Minute).Unix()),
		},
	}
}

// clientDomainOp is the third operation SEP-10 defines and the SDK rejects.
// Its source account is the client domain's signing key, not the server's.
func clientDomainOp() *txnbuild.ManageData {
	return &txnbuild.ManageData{
		SourceAccount: clientDomainKP.Address(),
		Name:          "client_domain",
		Value:         []byte(testClientDomain),
	}
}

// buildTx assembles and signs a transaction, returning its base64 XDR.
func buildTx(t *testing.T, params txnbuild.TransactionParams, signers ...*keypair.Full) string {
	t.Helper()

	tx, err := txnbuild.NewTransaction(params)
	require.NoError(t, err)

	if len(signers) > 0 {
		tx, err = tx.Sign(testNetwork, signers...)
		require.NoError(t, err)
	}

	xdrString, err := tx.Base64()
	require.NoError(t, err)
	return xdrString
}
