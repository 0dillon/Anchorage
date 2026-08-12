package auth

import (
	"context"
	"fmt"
	"time"

	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/strkey"
	"github.com/stellar/go-stellar-sdk/txnbuild"
)

// ClientDomainResolver returns the SIGNING_KEY published by a client domain.
type ClientDomainResolver interface {
	Resolve(ctx context.Context, domain string) (signingKey string, err error)
}

// IssuerConfig holds everything needed to issue challenges.
type IssuerConfig struct {
	// SigningSecret is the server's S... key. Never logged.
	SigningSecret        string
	NetworkPassphrase    string
	WebAuthDomain        string
	HomeDomains          []string
	ChallengeTimeout     time.Duration
	ClientDomainRequired bool
	Resolver             ClientDomainResolver
}

// Issuer builds SEP-10 challenges.
type Issuer struct {
	cfg      IssuerConfig
	signer   *keypair.Full
	homeSet  map[string]bool
	firstDom string
}

// NewIssuer validates the configuration and returns an Issuer.
func NewIssuer(cfg IssuerConfig) (*Issuer, error) {
	signer, err := keypair.ParseFull(cfg.SigningSecret)
	if err != nil {
		// Deliberately does not include the value.
		return nil, fmt.Errorf("signing secret is not a valid Stellar seed")
	}
	if len(cfg.HomeDomains) == 0 {
		return nil, fmt.Errorf("at least one home domain is required")
	}
	if cfg.ChallengeTimeout < time.Second {
		return nil, fmt.Errorf("challenge timeout must be at least 1s")
	}
	if cfg.Resolver == nil {
		return nil, fmt.Errorf("a client domain resolver is required")
	}

	homeSet := make(map[string]bool, len(cfg.HomeDomains))
	for _, domain := range cfg.HomeDomains {
		homeSet[domain] = true
	}

	return &Issuer{
		cfg:      cfg,
		signer:   signer,
		homeSet:  homeSet,
		firstDom: cfg.HomeDomains[0],
	}, nil
}

// IssueRequest is a parsed GET /auth request.
type IssueRequest struct {
	// Account is the client's G... or M... address.
	Account string
	// Memo is an optional ID memo. Never valid with an M... account.
	Memo *uint64
	// HomeDomain is optional; empty means the first configured domain.
	HomeDomain string
	// ClientDomain is the optional wallet domain.
	ClientDomain string
}

// IssuedChallenge is a challenge ready to return to the client and record in
// the store.
type IssuedChallenge struct {
	TransactionXDR    string
	NetworkPassphrase string
	Nonce             string
	Account           string
	HomeDomain        string
	ClientDomain      string
	ExpiresAt         time.Time
}

// ServerAccountID returns the server's public signing key.
func (i *Issuer) ServerAccountID() string {
	return i.signer.Address()
}

// Issue builds and signs a challenge for the request.
func (i *Issuer) Issue(ctx context.Context, req IssueRequest) (*IssuedChallenge, error) {
	isMuxed := strkey.IsValidMuxedAccountEd25519PublicKey(req.Account)
	if !isMuxed && !strkey.IsValidEd25519PublicKey(req.Account) {
		return nil, fmt.Errorf("%w: %q is not a G... or M... address", ErrInvalidAccount, req.Account)
	}

	// The SDK enforces this too. Failing early gives a clearer message.
	if req.Memo != nil && isMuxed {
		return nil, fmt.Errorf("%w: a muxed account already identifies the user", ErrMemoWithMuxed)
	}

	homeDomain := req.HomeDomain
	if homeDomain == "" {
		homeDomain = i.firstDom
	} else if !i.homeSet[homeDomain] {
		return nil, fmt.Errorf("%w: %q", ErrUnknownHomeDomain, homeDomain)
	}

	clientDomainKey := ""
	if req.ClientDomain != "" {
		key, err := i.cfg.Resolver.Resolve(ctx, req.ClientDomain)
		if err != nil {
			return nil, fmt.Errorf("%w: %s: %s", ErrClientDomainRejected, req.ClientDomain, err)
		}
		if key == "" {
			// A resolver that returns no error must return a key. If it returns
			// neither, that is a bug in the resolver, and the wrong way to absorb
			// it is to issue a challenge that silently drops the client_domain
			// operation: IssuedChallenge.ClientDomain would still say the domain
			// was bound when the signed transaction does not carry that binding.
			return nil, fmt.Errorf("%w: %s: resolver returned no signing key", ErrClientDomainRejected, req.ClientDomain)
		}
		clientDomainKey = key
	} else if i.cfg.ClientDomainRequired {
		return nil, fmt.Errorf("%w: this server requires a client_domain", ErrClientDomainRequired)
	}

	var memo *txnbuild.MemoID
	if req.Memo != nil {
		m := txnbuild.MemoID(*req.Memo)
		memo = &m
	}

	tx, err := txnbuild.BuildChallengeTx(
		i.cfg.SigningSecret,
		req.Account,
		i.cfg.WebAuthDomain,
		homeDomain,
		i.cfg.NetworkPassphrase,
		i.cfg.ChallengeTimeout,
		memo,
	)
	if err != nil {
		return nil, fmt.Errorf("building challenge: %w", err)
	}

	if clientDomainKey != "" {
		tx, err = i.appendClientDomain(tx, req.ClientDomain, clientDomainKey)
		if err != nil {
			return nil, err
		}
	}

	xdrString, err := tx.Base64()
	if err != nil {
		return nil, fmt.Errorf("encoding challenge: %w", err)
	}

	nonceOp, ok := tx.Operations()[0].(*txnbuild.ManageData)
	if !ok {
		return nil, fmt.Errorf("built challenge has no manage_data operation")
	}

	return &IssuedChallenge{
		TransactionXDR:    xdrString,
		NetworkPassphrase: i.cfg.NetworkPassphrase,
		Nonce:             string(nonceOp.Value),
		Account:           req.Account,
		HomeDomain:        homeDomain,
		ClientDomain:      req.ClientDomain,
		ExpiresAt:         time.Unix(tx.Timebounds().MaxTime, 0).UTC(),
	}, nil
}

// appendClientDomain adds the SEP-10 client_domain operation and re-signs.
//
// BuildChallengeTx signs before returning, and appending an operation
// invalidates that signature, so the transaction is rebuilt from its own parts
// and signed again. The discarded signature is the price of keeping nonce
// generation inside the SDK, where a subtle error would be both catastrophic
// and invisible. Do not "optimise" this by building the transaction directly.
func (i *Issuer) appendClientDomain(tx *txnbuild.Transaction, domain, signingKey string) (*txnbuild.Transaction, error) {
	if !strkey.IsValidEd25519PublicKey(signingKey) {
		return nil, fmt.Errorf("%w: %s published an invalid SIGNING_KEY", ErrClientDomainRejected, domain)
	}

	// The source account is the client domain's signing key, not the server's.
	// That is what makes the operation meaningful, and what the SDK's reader
	// rejects. See docs/sdk-findings.md.
	operations := append(tx.Operations(), &txnbuild.ManageData{
		SourceAccount: signingKey,
		Name:          opClientDomain,
		Value:         []byte(domain),
	})

	params := txnbuild.TransactionParams{
		SourceAccount: &txnbuild.SimpleAccount{
			AccountID: tx.SourceAccount().AccountID,
			Sequence:  0,
		},
		IncrementSequenceNum: false,
		Operations:           operations,
		BaseFee:              tx.BaseFee(),
		Preconditions: txnbuild.Preconditions{
			TimeBounds: tx.Timebounds(),
		},
	}
	// Assigned conditionally: a nil Memo in a struct literal is not a nil
	// interface. See https://go.dev/doc/faq#nil_error
	if memo := tx.Memo(); memo != nil {
		params.Memo = memo
	}

	rebuilt, err := txnbuild.NewTransaction(params)
	if err != nil {
		return nil, fmt.Errorf("rebuilding challenge with client domain: %w", err)
	}

	signed, err := rebuilt.Sign(i.cfg.NetworkPassphrase, i.signer)
	if err != nil {
		return nil, fmt.Errorf("re-signing challenge: %w", err)
	}
	return signed, nil
}
