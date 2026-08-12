package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

func TestHealthEndpoint(t *testing.T) {
	tests := []struct {
		name       string
		pingErr    error
		wantStatus int
		wantDB     string
	}{
		{"database up", nil, http.StatusOK, "ok"},
		{"database down", errors.New("connection refused"), http.StatusServiceUnavailable, "unavailable"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _ := newTestDeps(t)
			deps.Health = fakePinger{err: tt.pingErr}

			router, err := NewRouter(deps)
			require.NoError(t, err)

			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/health", nil))

			require.Equal(t, tt.wantStatus, rec.Code)

			var body map[string]string
			require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &body))
			require.Equal(t, tt.wantDB, body["database"])

			// The underlying error is never disclosed.
			if tt.pingErr != nil {
				require.NotContains(t, rec.Body.String(), "connection refused")
			}
		})
	}
}

func TestNewRouterRequiresDependencies(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Deps)
	}{
		{"no logger", func(d *Deps) { d.Logger = nil }},
		{"no health pinger", func(d *Deps) { d.Health = nil }},
		{"no issuer", func(d *Deps) { d.Issuer = nil }},
		{"no challenge store", func(d *Deps) { d.Challenges = nil }},
		{"no token issuer", func(d *Deps) { d.Tokens = nil }},
		{"no account fetcher", func(d *Deps) { d.Accounts = nil }},
		{"no web auth domain", func(d *Deps) { d.WebAuthDomain = "" }},
		{"no home domains", func(d *Deps) { d.HomeDomains = nil }},
		{"no network passphrase", func(d *Deps) { d.NetworkPassphrase = "" }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _ := newTestDeps(t)
			tt.mutate(&deps)

			_, err := NewRouter(deps)
			require.Error(t, err)
		})
	}
}
