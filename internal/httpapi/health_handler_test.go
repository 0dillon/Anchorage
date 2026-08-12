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
			router, err := NewRouter(Deps{
				Logger: discardLogger(),
				Health: fakePinger{err: tt.pingErr},
			})
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
	_, err := NewRouter(Deps{Health: fakePinger{}})
	require.Error(t, err)

	_, err = NewRouter(Deps{Logger: discardLogger()})
	require.Error(t, err)
}
