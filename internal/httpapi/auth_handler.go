package httpapi

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/0dillon/Anchorage/internal/store"
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
