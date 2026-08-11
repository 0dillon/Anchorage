package auth

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/xdr"
)

// Account is the subset of a Stellar account this package needs.
type Account struct {
	// Signers maps each signer's address to its weight.
	Signers map[string]int32
	// MedThreshold is the weight a SEP-10 authentication must reach.
	MedThreshold int32
}

// AccountFetcher looks up an account on the network. It returns
// ErrAccountNotFound when the account does not exist, which is a normal SEP-10
// case and not a failure.
type AccountFetcher interface {
	Account(ctx context.Context, accountID string) (*Account, error)
}

// VerifyClient checks the client's signatures on a challenge and returns the
// signers that were matched, excluding the server.
//
// An account that does not exist on the network is authenticated by its master
// key alone. An account that does exist must reach its medium threshold.
func VerifyClient(ctx context.Context, challenge *Challenge, networkPassphrase string, accounts AccountFetcher) ([]string, error) {
	accountID, err := baseAccountID(challenge.ClientAccountID)
	if err != nil {
		return nil, err
	}

	account, err := accounts.Account(ctx, accountID)
	switch {
	case errors.Is(err, ErrAccountNotFound):
		// No account on the network means no signer list and no thresholds.
		// The master key is the only key that can speak for it.
		return verifySigners(challenge, networkPassphrase, []string{accountID})

	case err != nil:
		// A lookup failure is our problem, not the caller's. Reporting it as a
		// signature failure would tell a caller their key was wrong when the
		// network was merely unreachable.
		return nil, fmt.Errorf("%w: %s", ErrAccountLookupFailed, err)
	}

	candidates := make([]string, 0, len(account.Signers))
	for signer := range account.Signers {
		candidates = append(candidates, signer)
	}
	// Map iteration order is random; sort so behaviour is deterministic.
	sort.Strings(candidates)

	found, err := verifySigners(challenge, networkPassphrase, candidates)
	if err != nil {
		return nil, err
	}

	weight := accountSignerWeight(found, account.Signers, challenge.ClientDomainKey)
	if weight < account.MedThreshold {
		return nil, fmt.Errorf("%w: matched weight %d against threshold %d",
			ErrThresholdNotMet, weight, account.MedThreshold)
	}

	return found, nil
}

// accountSignerWeight sums the weights of matched signers that belong to the
// account. The client domain key is excluded: it proves the wallet took part,
// never that the account authorised anything, and counting it would let any
// client domain meet any account's threshold.
//
// The exclusion applies even when the client domain key is also a signer on the
// account. That is deliberate: in the rare case where they are the same key,
// failing closed is the safe direction.
func accountSignerWeight(found []string, signers map[string]int32, clientDomainKey string) int32 {
	var weight int32
	for _, signer := range found {
		if clientDomainKey != "" && signer == clientDomainKey {
			continue
		}
		weight += signers[signer]
	}
	return weight
}

// verifySigners matches the challenge's signatures against the server and the
// given candidate signers. It mirrors txnbuild.VerifyChallengeTxSigners.
func verifySigners(challenge *Challenge, networkPassphrase string, accountSigners []string) ([]string, error) {
	serverAccountID := challenge.Tx.SourceAccount().AccountID

	clientSigners := make([]string, 0, len(accountSigners)+1)
	seen := make(map[string]bool, len(accountSigners)+1)
	add := func(signer string) {
		// The server never counts as a client signer. If an account happens to
		// have the server as a signer, the server must not authenticate on the
		// client's behalf.
		if signer == "" || signer == serverAccountID || seen[signer] {
			return
		}
		// Non-account strkeys (hash signers, pre-auth transactions) cannot sign
		// a challenge, so they are ignored rather than rejected.
		if !strkey.IsValidEd25519PublicKey(signer) {
			return
		}
		seen[signer] = true
		clientSigners = append(clientSigners, signer)
	}

	for _, signer := range accountSigners {
		add(signer)
	}
	// The client domain key must be a candidate. Its signature is on the
	// transaction, and the "all signatures accounted for" check below would
	// otherwise reject the challenge as carrying an unrecognised signature.
	add(challenge.ClientDomainKey)

	if len(clientSigners) == 0 {
		return nil, fmt.Errorf("%w: no verifiable signers for this account", ErrSignatureUnrecognized)
	}

	// Verify the server and the clients in one pass, so a single signature can
	// never be counted for two signers.
	all := make([]string, 0, len(clientSigners)+1)
	all = append(all, serverAccountID)
	all = append(all, clientSigners...)

	matched, err := matchSigners(challenge.Tx, networkPassphrase, all)
	if err != nil {
		return nil, err
	}

	serverFound := false
	found := make([]string, 0, len(matched))
	for _, signer := range matched {
		if signer == serverAccountID {
			serverFound = true
			continue
		}
		found = append(found, signer)
	}

	if !serverFound {
		return nil, fmt.Errorf("%w: challenge is not signed by this server", ErrSignatureUnrecognized)
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("%w: challenge carries no recognised client signature", ErrSignatureUnrecognized)
	}
	if len(matched) != len(challenge.Tx.Signatures()) {
		return nil, fmt.Errorf("%w: challenge carries unrecognised signatures", ErrSignatureUnrecognized)
	}

	if challenge.ClientDomainKey != "" {
		signed := false
		for _, signer := range found {
			if signer == challenge.ClientDomainKey {
				signed = true
				break
			}
		}
		if !signed {
			return nil, fmt.Errorf("%w: client domain %q did not sign the challenge",
				ErrClientDomainUnverified, challenge.ClientDomain)
		}
	}

	return found, nil
}

// baseAccountID reduces a muxed address to the underlying G... account, which
// is what Horizon knows about. A G... address is returned unchanged.
func baseAccountID(address string) (string, error) {
	if strkey.IsValidEd25519PublicKey(address) {
		return address, nil
	}

	muxed, err := xdr.AddressToMuxedAccount(address)
	if err != nil {
		return "", fmt.Errorf("%w: %q", ErrInvalidAccount, address)
	}
	return muxed.ToAccountId().Address(), nil
}
