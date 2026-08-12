package httpapi

import (
	"encoding/json"
	"errors"
	"log/slog"
	"mime"
	"net/http"
	"strconv"
	"time"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/0dillon/Anchorage/internal/store"
	"github.com/0dillon/Anchorage/internal/token"
	"github.com/stellar/go-stellar-sdk/txnbuild"
)

// sentinelStatus is the whole error mapping. Nothing else in this package
// assigns a status to a protocol error, and nothing matches on error strings.
//
// auth.ErrAccountNotFound is deliberately absent: a non-existent account is a
// normal SEP-10 case, authenticated by its master key, not a failure.
var sentinelStatus = []struct {
	err    error
	status int
}{
	{auth.ErrInvalidAccount, http.StatusBadRequest},
	{auth.ErrMemoWithMuxed, http.StatusBadRequest},
	{auth.ErrUnknownHomeDomain, http.StatusBadRequest},
	{auth.ErrClientDomainRequired, http.StatusBadRequest},
	{auth.ErrClientDomainRejected, http.StatusBadRequest},

	{auth.ErrChallengeMalformed, http.StatusUnauthorized},
	{auth.ErrChallengeUnknown, http.StatusUnauthorized},
	{auth.ErrChallengeConsumed, http.StatusUnauthorized},
	{auth.ErrChallengeExpired, http.StatusUnauthorized},
	{auth.ErrSignatureUnrecognized, http.StatusUnauthorized},
	{auth.ErrThresholdNotMet, http.StatusUnauthorized},
	{auth.ErrClientDomainUnverified, http.StatusUnauthorized},

	{auth.ErrAccountLookupFailed, http.StatusServiceUnavailable},
}

// classify returns the protocol sentinel err matches and the status it maps
// to, or (nil, 0) when err is not a protocol error at all. Callers decide what
// an unrecognised error means in their own context.
func classify(err error) (error, int) {
	for _, entry := range sentinelStatus {
		if errors.Is(err, entry.err) {
			return entry.err, entry.status
		}
	}
	return nil, 0
}

// respondError writes the failure class for a protocol error. The sentinel's
// own text is sent, not the wrapped error, so no internal detail leaks.
func respondError(w http.ResponseWriter, logger *slog.Logger, err error) {
	if sentinel, status := classify(err); sentinel != nil {
		writeError(w, logger, status, sentinel.Error())
		return
	}
	logger.Error("unhandled error", "error", err)
	writeError(w, logger, http.StatusInternalServerError, "internal server error")
}

// respondStoreError is respondError for a call into the store, where an
// unrecognised error is an outage rather than a bug.
func respondStoreError(w http.ResponseWriter, logger *slog.Logger, err error) {
	if sentinel, status := classify(err); sentinel != nil {
		writeError(w, logger, status, sentinel.Error())
		return
	}
	logger.Error("store failure", "error", err)
	writeError(w, logger, http.StatusServiceUnavailable, "service unavailable")
}

// challengeResponse is the body of GET /auth, as SEP-10 defines it.
type challengeResponse struct {
	Transaction       string `json:"transaction"`
	NetworkPassphrase string `json:"network_passphrase"`
}

// getAuthHandler serves GET /auth: build a challenge, record it, return it.
func getAuthHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		query := r.URL.Query()

		account := query.Get("account")
		if account == "" {
			writeError(w, d.Logger, http.StatusBadRequest, "account is required")
			return
		}

		memo, err := parseMemo(query.Get("memo"))
		if err != nil {
			writeError(w, d.Logger, http.StatusBadRequest, err.Error())
			return
		}

		issued, err := d.Issuer.Issue(r.Context(), auth.IssueRequest{
			Account:      account,
			Memo:         memo,
			HomeDomain:   query.Get("home_domain"),
			ClientDomain: query.Get("client_domain"),
		})
		if err != nil {
			respondError(w, d.Logger, err)
			return
		}

		// The challenge is recorded before it is returned. A challenge the
		// client holds but the server has no record of would be rejected as
		// unknown on the way back, so the write has to happen first.
		err = d.Challenges.RecordChallenge(r.Context(), store.ChallengeRecord{
			Nonce:        issued.Nonce,
			Account:      issued.Account,
			HomeDomain:   issued.HomeDomain,
			ClientDomain: issued.ClientDomain,
			IssuedAt:     time.Now().UTC(),
			ExpiresAt:    issued.ExpiresAt,
		})
		if err != nil {
			respondStoreError(w, d.Logger, err)
			return
		}

		writeJSON(w, d.Logger, http.StatusOK, challengeResponse{
			Transaction:       issued.TransactionXDR,
			NetworkPassphrase: issued.NetworkPassphrase,
		})
	}
}

// parseMemo reads the optional memo query parameter. SEP-10 memos are ID
// memos, so the value is an unsigned integer.
func parseMemo(raw string) (*uint64, error) {
	if raw == "" {
		return nil, nil
	}
	value, err := strconv.ParseUint(raw, 10, 64)
	if err != nil {
		return nil, errors.New("memo must be a positive integer")
	}
	return &value, nil
}

// tokenResponse is the body of POST /auth, as SEP-10 defines it.
type tokenResponse struct {
	Token string `json:"token"`
}

// postAuthHandler serves POST /auth: read the challenge, spend the nonce,
// verify the signatures, and mint a token.
func postAuthHandler(d Deps) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		envelope, err := readTransactionField(r)
		if err != nil {
			writeError(w, d.Logger, http.StatusBadRequest, err.Error())
			return
		}

		challenge, err := auth.ReadChallenge(envelope, d.Issuer.ServerAccountID(),
			d.NetworkPassphrase, d.WebAuthDomain, d.HomeDomains)
		if err != nil {
			respondError(w, d.Logger, err)
			return
		}

		// The nonce is spent BEFORE the signatures are checked. This ordering
		// is deliberate; do not reverse it.
		//
		// Verifying first would leave the challenge live through a failed
		// attempt, turning it into an unlimited retry oracle against a single
		// nonce — exactly the property replay protection exists to remove.
		// Spending first means one challenge buys one attempt.
		//
		// The cost is that a malformed or mis-signed submission burns the
		// challenge and the client must request another. That is one call, and
		// it is the cheaper side of the trade.
		now := time.Now().UTC()
		consumed, err := d.Challenges.ConsumeChallenge(r.Context(), challenge.Nonce, now)
		if err != nil {
			respondStoreError(w, d.Logger, err)
			return
		}

		// The stored record is authoritative. The server's signature already
		// proves the envelope is the one issued, so a mismatch here means the
		// two records disagree, which is a malformed challenge, not a client
		// error to explain.
		if consumed.Account != challenge.ClientAccountID ||
			consumed.ClientDomain != challenge.ClientDomain {
			d.Logger.Error("stored challenge disagrees with the posted envelope",
				"nonce", challenge.Nonce)
			respondError(w, d.Logger, auth.ErrChallengeMalformed)
			return
		}

		if _, err := auth.VerifyClient(r.Context(), challenge, d.NetworkPassphrase, d.Accounts); err != nil {
			respondError(w, d.Logger, err)
			return
		}

		// The jti is the hash of the challenge envelope, so a token can always
		// be traced back to the exact challenge that produced it.
		jti, err := challenge.Tx.HashHex(d.NetworkPassphrase)
		if err != nil {
			d.Logger.Error("hashing the challenge failed", "error", err)
			writeError(w, d.Logger, http.StatusInternalServerError, "internal server error")
			return
		}

		memo := memoValue(challenge.Memo)
		signed, err := d.Tokens.Issue(token.Request{
			Account:      challenge.ClientAccountID,
			Memo:         memo,
			ClientDomain: challenge.ClientDomain,
			JTI:          jti,
			IssuedAt:     now,
		})
		if err != nil {
			d.Logger.Error("issuing the token failed", "error", err)
			writeError(w, d.Logger, http.StatusInternalServerError, "internal server error")
			return
		}

		// The session is the audit trail. A failure to record it must not hand
		// out a token that was never written down.
		err = d.Challenges.RecordSession(r.Context(), store.SessionRecord{
			JTI:          jti,
			Account:      challenge.ClientAccountID,
			Memo:         memoString(memo),
			HomeDomain:   consumed.HomeDomain,
			ClientDomain: challenge.ClientDomain,
			IssuedAt:     now,
			ExpiresAt:    now.Add(d.Tokens.Lifetime()),
		})
		if err != nil {
			respondStoreError(w, d.Logger, err)
			return
		}

		writeJSON(w, d.Logger, http.StatusOK, tokenResponse{Token: signed})
	}
}

// readTransactionField reads the transaction from a JSON or form body. Both
// encodings are used in the wild.
func readTransactionField(r *http.Request) (string, error) {
	contentType := r.Header.Get("Content-Type")
	mediaType, _, err := mime.ParseMediaType(contentType)
	if err != nil {
		return "", errors.New("content-type is not valid")
	}

	switch mediaType {
	case "application/json":
		var body struct {
			Transaction string `json:"transaction"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			// The decode error can quote the body, so it is not passed on.
			return "", errors.New("request body is not valid JSON")
		}
		if body.Transaction == "" {
			return "", errors.New("transaction is required")
		}
		return body.Transaction, nil

	case "application/x-www-form-urlencoded":
		if err := r.ParseForm(); err != nil {
			return "", errors.New("request body is not a valid form")
		}
		value := r.PostForm.Get("transaction")
		if value == "" {
			return "", errors.New("transaction is required")
		}
		return value, nil

	default:
		return "", errors.New("content-type must be application/json or application/x-www-form-urlencoded")
	}
}

// memoValue converts the challenge's memo to the token package's form.
func memoValue(memo *txnbuild.MemoID) *uint64 {
	if memo == nil {
		return nil
	}
	value := uint64(*memo)
	return &value
}

// memoString renders a memo for the session row, empty when there is none.
func memoString(memo *uint64) string {
	if memo == nil {
		return ""
	}
	return strconv.FormatUint(*memo, 10)
}
