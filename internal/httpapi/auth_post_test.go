package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/stellar/go-stellar-sdk/keypair"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stretchr/testify/require"
)

// issueChallenge runs GET /auth through the router and returns the envelope.
func issueChallenge(t *testing.T, router http.Handler, query url.Values) string {
	t.Helper()

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth?"+query.Encode(), nil))
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Transaction string `json:"transaction"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	return body.Transaction
}

// signChallenge adds signatures to an envelope and re-encodes it.
func signChallenge(t *testing.T, envelope string, signers ...*keypair.Full) string {
	t.Helper()

	parsed, err := txnbuild.TransactionFromXDR(envelope)
	require.NoError(t, err)
	tx, ok := parsed.Transaction()
	require.True(t, ok)

	signed, err := tx.Sign(testNetwork, signers...)
	require.NoError(t, err)

	encoded, err := signed.Base64()
	require.NoError(t, err)
	return encoded
}

// postAuthJSON posts a signed envelope as JSON.
func postAuthJSON(t *testing.T, router http.Handler, envelope string) *httptest.ResponseRecorder {
	t.Helper()

	body, err := json.Marshal(map[string]string{"transaction": envelope})
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

func TestPostAuthReturnsAToken(t *testing.T) {
	deps, fake := newTestDeps(t)
	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{"account": {clientKP.Address()}})
	rec := postAuthJSON(t, router, signChallenge(t, envelope, clientKP))
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.NotEmpty(t, body.Token)

	claims, err := deps.Tokens.Parse(body.Token, time.Now())
	require.NoError(t, err)
	require.Equal(t, clientKP.Address(), claims.Subject)
	require.Empty(t, claims.ClientDomain)
	require.NotEmpty(t, claims.ID)

	// The session was recorded, keyed by the same jti the token carries.
	require.Len(t, fake.sessions, 1)
	require.Equal(t, claims.ID, fake.sessions[0].JTI)
	require.Equal(t, testHomeDomain, fake.sessions[0].HomeDomain)
}

// The same challenge cannot be answered twice. This is the replay check.
func TestPostAuthRejectsReplay(t *testing.T) {
	deps, _ := newTestDeps(t)
	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{"account": {clientKP.Address()}})
	signed := signChallenge(t, envelope, clientKP)

	require.Equal(t, http.StatusOK, postAuthJSON(t, router, signed).Code)

	second := postAuthJSON(t, router, signed)
	require.Equal(t, http.StatusUnauthorized, second.Code)

	var body map[string]string
	require.NoError(t, json.Unmarshal(second.Body.Bytes(), &body))
	require.Equal(t, auth.ErrChallengeConsumed.Error(), body["error"])
}

// The form encoding is accepted too. Both are used in the wild.
func TestPostAuthAcceptsFormEncoding(t *testing.T) {
	deps, _ := newTestDeps(t)
	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{"account": {clientKP.Address()}})
	form := url.Values{"transaction": {signChallenge(t, envelope, clientKP)}}

	req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
}

func TestPostAuthWithMemoAndClientDomain(t *testing.T) {
	deps, fake := newTestDeps(t)
	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{
		"account":       {clientKP.Address()},
		"memo":          {"1234"},
		"client_domain": {testClientDomain},
	})
	rec := postAuthJSON(t, router, signChallenge(t, envelope, clientKP, clientDomainKP))
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Token string `json:"token"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	claims, err := deps.Tokens.Parse(body.Token, time.Now())
	require.NoError(t, err)
	require.Equal(t, clientKP.Address()+":1234", claims.Subject)
	require.Equal(t, testClientDomain, claims.ClientDomain)

	require.Len(t, fake.sessions, 1)
	require.Equal(t, "1234", fake.sessions[0].Memo)
	require.Equal(t, testClientDomain, fake.sessions[0].ClientDomain)
}

// A challenge carrying client_domain that the client domain did not sign is
// refused, even when the account's own signature is perfectly good.
func TestPostAuthRequiresClientDomainSignature(t *testing.T) {
	deps, _ := newTestDeps(t)
	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{
		"account":       {clientKP.Address()},
		"client_domain": {testClientDomain},
	})
	rec := postAuthJSON(t, router, signChallenge(t, envelope, clientKP))
	require.Equal(t, http.StatusUnauthorized, rec.Code)
}

func TestPostAuthUnauthorized(t *testing.T) {
	other := mustKeypair(9)

	tests := []struct {
		name    string
		signers []*keypair.Full
		want    error
	}{
		{"no client signature", nil, auth.ErrSignatureUnrecognized},
		{"wrong signer", []*keypair.Full{other}, auth.ErrSignatureUnrecognized},
		{"account signer plus a stranger", []*keypair.Full{clientKP, other}, auth.ErrSignatureUnrecognized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _ := newTestDeps(t)
			router, err := NewRouter(deps)
			require.NoError(t, err)

			envelope := issueChallenge(t, router, url.Values{"account": {clientKP.Address()}})
			rec := postAuthJSON(t, router, signChallenge(t, envelope, tt.signers...))
			require.Equal(t, http.StatusUnauthorized, rec.Code)

			var body map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.Equal(t, tt.want.Error(), body["error"])
		})
	}
}

// An account whose signer does not carry enough weight is refused.
func TestPostAuthRejectsInsufficientWeight(t *testing.T) {
	deps, _ := newTestDeps(t)
	deps.Accounts = fakeAccounts{account: &auth.Account{
		Signers:      map[string]int32{clientKP.Address(): 1},
		MedThreshold: 5,
	}}

	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{"account": {clientKP.Address()}})
	rec := postAuthJSON(t, router, signChallenge(t, envelope, clientKP))
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, auth.ErrThresholdNotMet.Error(), body["error"])
}

// A non-existent account authenticates on its master key alone.
func TestPostAuthAcceptsNonExistentAccount(t *testing.T) {
	deps, _ := newTestDeps(t)
	deps.Accounts = fakeAccounts{err: auth.ErrAccountNotFound}

	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{"account": {clientKP.Address()}})
	rec := postAuthJSON(t, router, signChallenge(t, envelope, clientKP))
	require.Equal(t, http.StatusOK, rec.Code)
}

// A Horizon outage is 503, never 401. Reporting it as a bad signature would
// tell a caller their key is wrong when it is not.
func TestPostAuthHorizonOutageIs503(t *testing.T) {
	deps, _ := newTestDeps(t)
	deps.Accounts = fakeAccounts{err: auth.ErrAccountLookupFailed}

	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{"account": {clientKP.Address()}})
	rec := postAuthJSON(t, router, signChallenge(t, envelope, clientKP))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
}

func TestPostAuthBadRequests(t *testing.T) {
	tests := []struct {
		name        string
		contentType string
		body        string
		wantStatus  int
	}{
		{"empty json body", "application/json", `{}`, http.StatusBadRequest},
		{"malformed json", "application/json", `{`, http.StatusBadRequest},
		{"empty form", "application/x-www-form-urlencoded", "", http.StatusBadRequest},
		{"unsupported content type", "text/plain", "whatever", http.StatusBadRequest},
		{"transaction is not xdr", "application/json", `{"transaction":"not-xdr"}`, http.StatusUnauthorized},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _ := newTestDeps(t)
			router, err := NewRouter(deps)
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost, "/auth", strings.NewReader(tt.body))
			req.Header.Set("Content-Type", tt.contentType)

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			require.Equal(t, tt.wantStatus, rec.Code)
		})
	}
}

// A challenge this server never issued is unknown, however well it is signed.
func TestPostAuthRejectsForeignChallenge(t *testing.T) {
	deps, _ := newTestDeps(t)
	router, err := NewRouter(deps)
	require.NoError(t, err)

	// Issued by a router with its own store, so this router has no record of
	// the nonce.
	otherDeps, _ := newTestDeps(t)
	otherRouter, err := NewRouter(otherDeps)
	require.NoError(t, err)

	envelope := issueChallenge(t, otherRouter, url.Values{"account": {clientKP.Address()}})
	rec := postAuthJSON(t, router, signChallenge(t, envelope, clientKP))
	require.Equal(t, http.StatusUnauthorized, rec.Code)

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, auth.ErrChallengeUnknown.Error(), body["error"])
}

// A store outage during consumption is 503, not a replay rejection.
func TestPostAuthStoreFailureIs503(t *testing.T) {
	deps, fake := newTestDeps(t)
	router, err := NewRouter(deps)
	require.NoError(t, err)

	envelope := issueChallenge(t, router, url.Values{"account": {clientKP.Address()}})
	fake.consumeErr = errors.New("connection refused")

	rec := postAuthJSON(t, router, signChallenge(t, envelope, clientKP))
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.NotContains(t, rec.Body.String(), "connection refused")
}

// Every sentinel has a status, and the table has no entries beyond them. This
// is the test that fails when a sentinel is added and left unmapped.
func TestClassifyCoversEverySentinel(t *testing.T) {
	tests := []struct {
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

	require.Len(t, sentinelStatus, len(tests),
		"a sentinel was added to or removed from the mapping without updating this test")

	for _, tt := range tests {
		t.Run(tt.err.Error(), func(t *testing.T) {
			// Wrapped, because that is how handlers receive them.
			sentinel, status := classify(errors.Join(errors.New("context"), tt.err))
			require.Equal(t, tt.err, sentinel)
			require.Equal(t, tt.status, status)
		})
	}
}

// ErrAccountNotFound is deliberately unmapped. It is a normal SEP-10 case, not
// a failure, and giving it a status would turn a valid login into an error.
func TestClassifyIgnoresAccountNotFound(t *testing.T) {
	sentinel, status := classify(auth.ErrAccountNotFound)
	require.Nil(t, sentinel)
	require.Zero(t, status)
}

// An error that is not a protocol error at all falls through to the caller's
// own default.
func TestClassifyIgnoresUnknownErrors(t *testing.T) {
	sentinel, status := classify(errors.New("connection refused"))
	require.Nil(t, sentinel)
	require.Zero(t, status)
}
