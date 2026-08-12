package account

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/0dillon/Anchorage/internal/auth"
	"github.com/stretchr/testify/require"
)

// Fetcher must satisfy the interface internal/auth declares.
var _ auth.AccountFetcher = (*Fetcher)(nil)

const accountID = "GA7QYNF7SOWQ3GLR2BGMZEHXAVIRZA4KVWLTJJFC7MGXUA74P7UJVSGZ"

// accountJSON is a trimmed Horizon account response. Only the fields the
// fetcher reads are present; Horizon sends many more and the decoder ignores
// them.
const accountJSON = `{
  "id": "` + accountID + `",
  "account_id": "` + accountID + `",
  "sequence": "12345",
  "thresholds": {"low_threshold": 0, "med_threshold": 2, "high_threshold": 3},
  "signers": [
    {"key": "` + accountID + `", "weight": 1, "type": "ed25519_public_key"},
    {"key": "GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H", "weight": 2, "type": "ed25519_public_key"}
  ]
}`

// newTestFetcher points a Fetcher at a test server and returns both.
func newTestFetcher(t *testing.T, h http.HandlerFunc) (*Fetcher, *httptest.Server) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)

	f, err := NewFetcher(srv.URL, srv.Client())
	require.NoError(t, err)
	return f, srv
}

func TestAccountReadsSignersAndThreshold(t *testing.T) {
	var gotPath string
	f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(accountJSON))
	})

	acct, err := f.Account(context.Background(), accountID)
	require.NoError(t, err)

	require.Equal(t, "/accounts/"+accountID, gotPath)
	require.Equal(t, int32(2), acct.MedThreshold)
	require.Equal(t, map[string]int32{
		accountID: 1,
		"GBRPYHIL2CI3FNQ4BXLFMNDLFJUNPU2HY3ZMFSHONUCEOASW7QC7OX2H": 2,
	}, acct.Signers)
}

// A 404 is not a failure. SEP-10 authenticates a non-existent account by its
// master key alone, so the caller needs to tell this apart from an outage.
func TestAccountNotFound(t *testing.T) {
	f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte(`{"status": 404, "title": "Resource Missing"}`))
	})

	_, err := f.Account(context.Background(), accountID)
	require.ErrorIs(t, err, auth.ErrAccountNotFound)
}

// Every other Horizon failure is an outage. It must never be reported as a
// missing account, because that would authenticate on the master key alone.
func TestAccountLookupFailures(t *testing.T) {
	tests := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "server error",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
		},
		{
			name: "rate limited",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
			},
		},
		{
			name: "body is not json",
			handler: func(w http.ResponseWriter, r *http.Request) {
				_, _ = w.Write([]byte("<html>gateway</html>"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, _ := newTestFetcher(t, tt.handler)

			_, err := f.Account(context.Background(), accountID)
			require.ErrorIs(t, err, auth.ErrAccountLookupFailed)
			require.NotErrorIs(t, err, auth.ErrAccountNotFound)
		})
	}
}

// An oversized body is refused rather than truncated. A truncated JSON body
// would fail to decode anyway, but failing on the size is the honest error.
func TestAccountRejectsOversizedBody(t *testing.T) {
	f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		big := make([]byte, maxAccountBytes+1)
		for i := range big {
			big[i] = ' '
		}
		_, _ = w.Write(big)
	})

	_, err := f.Account(context.Background(), accountID)
	require.ErrorIs(t, err, auth.ErrAccountLookupFailed)
	require.Contains(t, err.Error(), "too large")
}

// The context is honoured. This is the whole reason the package exists.
func TestAccountHonoursContextCancellation(t *testing.T) {
	f, _ := newTestFetcher(t, func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(accountJSON))
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := f.Account(ctx, accountID)
	require.ErrorIs(t, err, auth.ErrAccountLookupFailed)
	require.ErrorIs(t, err, context.Canceled)
}

func TestNewFetcherRejectsBadURL(t *testing.T) {
	_, err := NewFetcher("", http.DefaultClient)
	require.Error(t, err)

	_, err = NewFetcher("not-a-url", http.DefaultClient)
	require.Error(t, err)
}
