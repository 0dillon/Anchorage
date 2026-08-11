// Package auth implements the SEP-10 challenge protocol: issuing challenges,
// reading them back, and verifying client signatures against an account.
package auth

import "errors"

// Errors that mean the caller's request was bad. Handlers map these to 400.
var (
	// ErrInvalidAccount means the account is not a G... or M... strkey.
	ErrInvalidAccount = errors.New("account is not a valid Stellar address")
	// ErrMemoWithMuxed means a memo was combined with an M... account.
	ErrMemoWithMuxed = errors.New("memo is not valid with a muxed account")
	// ErrUnknownHomeDomain means the home domain is not configured.
	ErrUnknownHomeDomain = errors.New("home domain is not served by this server")
	// ErrClientDomainRequired means client_domain is mandatory but absent.
	ErrClientDomainRequired = errors.New("client domain is required")
	// ErrClientDomainRejected means the client domain could not be resolved or
	// is not on the allowlist.
	ErrClientDomainRejected = errors.New("client domain was rejected")
)

// Errors that mean verification failed. Handlers map these to 401 and must not
// disclose which one it was beyond the failure class.
var (
	// ErrChallengeMalformed means the challenge is not a well-formed SEP-10
	// challenge for this server.
	ErrChallengeMalformed = errors.New("challenge is malformed")
	// ErrChallengeUnknown means the nonce was never issued by this server.
	ErrChallengeUnknown = errors.New("challenge is not recognised")
	// ErrChallengeConsumed means the nonce was already used. A challenge is
	// valid exactly once.
	ErrChallengeConsumed = errors.New("challenge has already been used")
	// ErrChallengeExpired means the challenge is outside its timebounds or past
	// its stored expiry.
	ErrChallengeExpired = errors.New("challenge has expired")
	// ErrSignatureUnrecognized means a signature on the challenge matched no
	// expected signer, or an expected signature was missing.
	ErrSignatureUnrecognized = errors.New("challenge signatures are not recognised")
	// ErrThresholdNotMet means the matched account signers did not reach the
	// account's medium threshold.
	ErrThresholdNotMet = errors.New("signature weight does not meet the account threshold")
	// ErrClientDomainUnverified means the challenge carried a client_domain
	// operation that the client domain's signing key did not sign.
	ErrClientDomainUnverified = errors.New("client domain signature is missing")
)

// Errors that mean a dependency failed, not the caller. Handlers map these to
// 503. An outage must never be reported as a bad signature.
var (
	// ErrAccountLookupFailed means Horizon could not be consulted. It is
	// distinct from ErrAccountNotFound, which is a normal SEP-10 case.
	ErrAccountLookupFailed = errors.New("account lookup failed")
)

// ErrAccountNotFound means the account does not exist on the network. This is
// not a failure: SEP-10 authenticates such an account by its master key alone.
// An AccountFetcher returns it; no handler maps it to a status code.
var ErrAccountNotFound = errors.New("account does not exist on the network")
