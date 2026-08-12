package httpapi

import (
	"bytes"
	"fmt"
	"log/slog"
	"net/http"
	"os"
)

// signingKeyPlaceholder is replaced with the server's public signing key when
// the SEP-1 file is loaded.
const signingKeyPlaceholder = "${SIGNING_KEY}"

// loadTOML reads the SEP-1 file and substitutes the signing key.
//
// The placeholder is required. A file that hard-codes SIGNING_KEY could name a
// key this server cannot sign with, and every client that read it would build
// challenges nobody can answer.
func loadTOML(path, signingKey string) ([]byte, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading the SEP-1 file at %s: %w", path, err)
	}

	placeholder := []byte(signingKeyPlaceholder)
	if !bytes.Contains(raw, placeholder) {
		return nil, fmt.Errorf(
			"the SEP-1 file at %s must contain the %s placeholder, not a literal signing key",
			path, signingKeyPlaceholder)
	}

	return bytes.ReplaceAll(raw, placeholder, []byte(signingKey)), nil
}

// tomlHandler serves the SEP-1 file. It is read once at startup, so a request
// never touches the disk and a file changed underneath a running server has no
// effect until it restarts.
//
// The CORS header is permissive because the file is public by design: wallets
// fetch it from arbitrary origins to discover this server.
func tomlHandler(body []byte, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.WriteHeader(http.StatusOK)

		if _, err := w.Write(body); err != nil {
			logger.Warn("writing stellar.toml failed", "error", err)
		}
	}
}
