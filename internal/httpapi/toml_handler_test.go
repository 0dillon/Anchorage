package httpapi

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// writeTOML writes a temporary SEP-1 file and returns its path.
func writeTOML(t *testing.T, contents string) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "stellar.toml")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func TestTOMLEndpointServesTheFile(t *testing.T) {
	deps, _ := newTestDeps(t)
	deps.TOMLPath = writeTOML(t, "VERSION = \"2.0.0\"\nSIGNING_KEY = \"${SIGNING_KEY}\"\n")
	deps.SigningPublicKey = serverKP.Address()

	router, err := NewRouter(deps)
	require.NoError(t, err)

	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/.well-known/stellar.toml", nil))

	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "text/plain; charset=utf-8", rec.Header().Get("Content-Type"))
	require.Equal(t, "*", rec.Header().Get("Access-Control-Allow-Origin"))

	// The placeholder is gone and the real key is in its place.
	require.NotContains(t, rec.Body.String(), signingKeyPlaceholder)
	require.Contains(t, rec.Body.String(), serverKP.Address())
}

// A missing file fails startup. It must not produce a server that serves an
// empty or wrong SEP-1 document.
func TestNewRouterFailsOnMissingTOML(t *testing.T) {
	deps, _ := newTestDeps(t)
	deps.TOMLPath = filepath.Join(t.TempDir(), "does-not-exist.toml")
	deps.SigningPublicKey = serverKP.Address()

	_, err := NewRouter(deps)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does-not-exist.toml")
}

// A file with a hard-coded key fails startup too. Substituting at load is what
// stops a mismatched key being published, and a file with nothing to
// substitute defeats it.
func TestNewRouterFailsWithoutPlaceholder(t *testing.T) {
	deps, _ := newTestDeps(t)
	deps.TOMLPath = writeTOML(t, "VERSION = \"2.0.0\"\nSIGNING_KEY = \"GSOMEOTHERKEY\"\n")
	deps.SigningPublicKey = serverKP.Address()

	_, err := NewRouter(deps)
	require.Error(t, err)
	require.Contains(t, err.Error(), signingKeyPlaceholder)
}

func TestNewRouterRequiresTOMLSettings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Deps)
	}{
		{"no toml path", func(d *Deps) { d.TOMLPath = "" }},
		{"no signing public key", func(d *Deps) { d.SigningPublicKey = "" }},
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

func TestLoadTOMLReplacesEveryOccurrence(t *testing.T) {
	path := writeTOML(t, "A = \"${SIGNING_KEY}\"\nB = \"${SIGNING_KEY}\"\n")

	body, err := loadTOML(path, serverKP.Address())
	require.NoError(t, err)
	require.NotContains(t, string(body), signingKeyPlaceholder)
	require.Equal(t,
		"A = \""+serverKP.Address()+"\"\nB = \""+serverKP.Address()+"\"\n",
		string(body))
}
