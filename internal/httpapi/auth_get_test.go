package httpapi

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/stellar/go-stellar-sdk/txnbuild"
	"github.com/stretchr/testify/require"
)

// getAuth issues a challenge through the router and returns the recorder.
func getAuth(t *testing.T, deps Deps, query url.Values) *httptest.ResponseRecorder {
	t.Helper()

	router, err := NewRouter(deps)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/auth?"+query.Encode(), nil))
	return rec
}

func TestGetAuthReturnsAChallenge(t *testing.T) {
	deps, fake := newTestDeps(t)

	rec := getAuth(t, deps, url.Values{"account": {clientKP.Address()}})
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "application/json", rec.Header().Get("Content-Type"))

	var body struct {
		Transaction       string `json:"transaction"`
		NetworkPassphrase string `json:"network_passphrase"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, testNetwork, body.NetworkPassphrase)
	require.NotEmpty(t, body.Transaction)

	// The challenge is readable and was recorded under its own nonce.
	challenge, err := auth.ReadChallenge(body.Transaction, serverKP.Address(),
		testNetwork, testWebAuthDomain, []string{testHomeDomain})
	require.NoError(t, err)

	require.Len(t, fake.challenges, 1)
	recorded, ok := fake.challenges[challenge.Nonce]
	require.True(t, ok, "the challenge was recorded under its nonce")
	require.Equal(t, clientKP.Address(), recorded.Account)
	require.Equal(t, testHomeDomain, recorded.HomeDomain)
	require.Empty(t, recorded.ClientDomain)
}

func TestGetAuthWithClientDomain(t *testing.T) {
	deps, fake := newTestDeps(t)

	rec := getAuth(t, deps, url.Values{
		"account":       {clientKP.Address()},
		"client_domain": {testClientDomain},
	})
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Transaction string `json:"transaction"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	challenge, err := auth.ReadChallenge(body.Transaction, serverKP.Address(),
		testNetwork, testWebAuthDomain, []string{testHomeDomain})
	require.NoError(t, err)
	require.Equal(t, testClientDomain, challenge.ClientDomain)
	require.Equal(t, clientDomainKP.Address(), challenge.ClientDomainKey)

	require.Equal(t, testClientDomain, fake.challenges[challenge.Nonce].ClientDomain)
}

func TestGetAuthWithMemo(t *testing.T) {
	deps, _ := newTestDeps(t)

	rec := getAuth(t, deps, url.Values{
		"account": {clientKP.Address()},
		"memo":    {"1234"},
	})
	require.Equal(t, http.StatusOK, rec.Code)

	var body struct {
		Transaction string `json:"transaction"`
	}
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))

	challenge, err := auth.ReadChallenge(body.Transaction, serverKP.Address(),
		testNetwork, testWebAuthDomain, []string{testHomeDomain})
	require.NoError(t, err)
	require.NotNil(t, challenge.Memo)
	require.Equal(t, txnbuild.MemoID(1234), *challenge.Memo)
}

func TestGetAuthBadRequests(t *testing.T) {
	tests := []struct {
		name  string
		query url.Values
		want  string
	}{
		{
			name:  "no account",
			query: url.Values{},
			want:  "account is required",
		},
		{
			name:  "account is not a strkey",
			query: url.Values{"account": {"not-an-account"}},
			want:  auth.ErrInvalidAccount.Error(),
		},
		{
			name:  "memo is not a number",
			query: url.Values{"account": {clientKP.Address()}, "memo": {"abc"}},
			want:  "memo must be a positive integer",
		},
		{
			name:  "memo is negative",
			query: url.Values{"account": {clientKP.Address()}, "memo": {"-1"}},
			want:  "memo must be a positive integer",
		},
		{
			name:  "unknown home domain",
			query: url.Values{"account": {clientKP.Address()}, "home_domain": {"evil.example.com"}},
			want:  auth.ErrUnknownHomeDomain.Error(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _ := newTestDeps(t)

			rec := getAuth(t, deps, tt.query)
			require.Equal(t, http.StatusBadRequest, rec.Code)

			var body map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.Equal(t, tt.want, body["error"])
		})
	}
}

// A client domain that cannot be resolved is the caller's problem, not ours.
func TestGetAuthRejectsUnresolvableClientDomain(t *testing.T) {
	deps, _ := newTestDeps(t)
	deps.Issuer = testIssuer(t, fakeResolver{err: errors.New("dns failure")})

	rec := getAuth(t, deps, url.Values{
		"account":       {clientKP.Address()},
		"client_domain": {testClientDomain},
	})
	require.Equal(t, http.StatusBadRequest, rec.Code)

	// The resolver's own message must not reach the caller.
	require.NotContains(t, rec.Body.String(), "dns failure")

	var body map[string]string
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
	require.Equal(t, auth.ErrClientDomainRejected.Error(), body["error"])
}

// A store outage is 503. It must never look like a rejected request, because
// the caller would retry with different input and get nowhere.
func TestGetAuthStoreFailureIs503(t *testing.T) {
	deps, fake := newTestDeps(t)
	fake.recordErr = errors.New("connection refused")

	rec := getAuth(t, deps, url.Values{"account": {clientKP.Address()}})
	require.Equal(t, http.StatusServiceUnavailable, rec.Code)
	require.NotContains(t, rec.Body.String(), "connection refused")
}
