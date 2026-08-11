package auth

import (
	"encoding/base64"
	"fmt"
	"time"

	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
)

const (
	// clockGracePeriod allows for drift between the client's clock and ours.
	// It matches the SDK's reader.
	clockGracePeriod = 5 * time.Minute
	// A SEP-10 nonce is 48 random bytes, which is 64 base64 characters.
	nonceEncodedLen = 64
	nonceRawLen     = 48

	opWebAuthDomain = "web_auth_domain"
	opClientDomain  = "client_domain"
)

// Challenge is a SEP-10 challenge transaction that has been read and
// structurally validated. Its signatures beyond the server's are not yet
// checked; see VerifyClient.
type Challenge struct {
	// Tx is the parsed transaction, needed to verify signatures and to compute
	// the JWT's jti.
	Tx *txnbuild.Transaction
	// ClientAccountID is the account being authenticated, G... or M...
	ClientAccountID string
	// HomeDomain is the configured domain the challenge matched.
	HomeDomain string
	// Memo is the ID memo, when one was used. Never set for a muxed account.
	Memo *txnbuild.MemoID
	// Nonce is the base64 nonce from the first operation. It is the replay key.
	Nonce string
	// ClientDomain is the wallet's domain, empty when the challenge carries no
	// client_domain operation.
	ClientDomain string
	// ClientDomainKey is the signing key that operation was sourced at, empty
	// when there is no client_domain operation.
	ClientDomainKey string
}

// ReadChallenge parses a SEP-10 challenge and validates its structure against
// this server's identity and configured home domains. It confirms the server
// signed the challenge; it does not check the client's signatures.
//
// It exists because txnbuild.ReadChallengeTx rejects the client_domain
// operation that SEP-10 defines. See docs/sdk-findings.md. Behaviour is
// otherwise identical to the SDK's reader, which differential_test.go asserts.
func ReadChallenge(challengeXDR, serverAccountID, networkPassphrase, webAuthDomain string, homeDomains []string) (*Challenge, error) {
	generic, err := txnbuild.TransactionFromXDR(challengeXDR)
	if err != nil {
		return nil, fmt.Errorf("%w: could not parse challenge XDR", ErrChallengeMalformed)
	}

	tx, ok := generic.Transaction()
	if !ok {
		return nil, fmt.Errorf("%w: challenge must not be a fee bump transaction", ErrChallengeMalformed)
	}

	source := tx.SourceAccount()
	if !strkey.IsValidEd25519PublicKey(source.AccountID) {
		return nil, fmt.Errorf("%w: transaction source must be a G... account", ErrChallengeMalformed)
	}
	if source.AccountID != serverAccountID {
		return nil, fmt.Errorf("%w: transaction source is not this server", ErrChallengeMalformed)
	}
	if source.Sequence != 0 {
		return nil, fmt.Errorf("%w: transaction sequence number must be 0", ErrChallengeMalformed)
	}

	bounds := tx.Timebounds()
	if bounds.MaxTime == txnbuild.TimeoutInfinite {
		return nil, fmt.Errorf("%w: challenge requires finite timebounds", ErrChallengeMalformed)
	}
	now := time.Now().UTC().Unix()
	grace := int64(clockGracePeriod / time.Second)
	if now+grace < bounds.MinTime || now > bounds.MaxTime {
		return nil, fmt.Errorf("%w: challenge is outside its timebounds", ErrChallengeExpired)
	}

	ops := tx.Operations()
	if len(ops) < 1 {
		return nil, fmt.Errorf("%w: challenge requires at least one manage_data operation", ErrChallengeMalformed)
	}

	first, ok := ops[0].(*txnbuild.ManageData)
	if !ok {
		return nil, fmt.Errorf("%w: first operation must be manage_data", ErrChallengeMalformed)
	}
	if first.SourceAccount == "" {
		return nil, fmt.Errorf("%w: first operation must have a source account", ErrChallengeMalformed)
	}

	challenge := &Challenge{Tx: tx}

	for _, homeDomain := range homeDomains {
		if first.Name == homeDomain+" auth" {
			challenge.HomeDomain = homeDomain
			break
		}
	}
	if challenge.HomeDomain == "" {
		return nil, fmt.Errorf("%w: operation key %q matches no configured home domain",
			ErrUnknownHomeDomain, first.Name)
	}

	isMuxed := strkey.IsValidMuxedAccountEd25519PublicKey(first.SourceAccount)
	if !isMuxed && !strkey.IsValidEd25519PublicKey(first.SourceAccount) {
		return nil, fmt.Errorf("%w: first operation source must be a G... or M... account", ErrChallengeMalformed)
	}
	challenge.ClientAccountID = first.SourceAccount

	if memo := tx.Memo(); memo != nil {
		if isMuxed {
			return nil, fmt.Errorf("%w: challenge carries both a memo and a muxed account", ErrMemoWithMuxed)
		}
		id, isID := memo.(txnbuild.MemoID)
		if !isID {
			return nil, fmt.Errorf("%w: only ID memos are permitted", ErrChallengeMalformed)
		}
		challenge.Memo = &id
	}

	challenge.Nonce = string(first.Value)
	if len(challenge.Nonce) != nonceEncodedLen {
		return nil, fmt.Errorf("%w: nonce must be %d base64 characters", ErrChallengeMalformed, nonceEncodedLen)
	}
	raw, err := base64.StdEncoding.DecodeString(challenge.Nonce)
	if err != nil {
		return nil, fmt.Errorf("%w: nonce is not valid base64", ErrChallengeMalformed)
	}
	if len(raw) != nonceRawLen {
		return nil, fmt.Errorf("%w: nonce must decode to %d bytes", ErrChallengeMalformed, nonceRawLen)
	}

	for _, op := range ops[1:] {
		data, isManageData := op.(*txnbuild.ManageData)
		if !isManageData {
			return nil, fmt.Errorf("%w: every operation must be manage_data", ErrChallengeMalformed)
		}
		if data.SourceAccount == "" {
			return nil, fmt.Errorf("%w: operation %q must have a source account", ErrChallengeMalformed, data.Name)
		}

		switch data.Name {
		case opWebAuthDomain:
			if data.SourceAccount != serverAccountID {
				return nil, fmt.Errorf("%w: web_auth_domain operation must be sourced at the server", ErrChallengeMalformed)
			}
			if string(data.Value) != webAuthDomain {
				return nil, fmt.Errorf("%w: web_auth_domain operation names a different server", ErrChallengeMalformed)
			}

		case opClientDomain:
			// The rule the SDK lacks. SEP-10 requires this operation to be
			// sourced at the client domain's SIGNING_KEY, not at the server,
			// because the client domain is what signs it.
			if !strkey.IsValidEd25519PublicKey(data.SourceAccount) {
				return nil, fmt.Errorf("%w: client_domain operation must be sourced at a G... signing key", ErrChallengeMalformed)
			}
			if len(data.Value) == 0 {
				return nil, fmt.Errorf("%w: client_domain operation must name a domain", ErrChallengeMalformed)
			}
			challenge.ClientDomain = string(data.Value)
			challenge.ClientDomainKey = data.SourceAccount

		default:
			if data.SourceAccount != serverAccountID {
				return nil, fmt.Errorf("%w: unrecognised operation %q", ErrChallengeMalformed, data.Name)
			}
		}
	}

	serverFound, err := matchSigners(tx, networkPassphrase, []string{serverAccountID})
	if err != nil {
		return nil, err
	}
	if len(serverFound) == 0 {
		return nil, fmt.Errorf("%w: challenge is not signed by this server", ErrChallengeMalformed)
	}

	return challenge, nil
}
