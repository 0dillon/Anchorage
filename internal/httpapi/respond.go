// Package httpapi serves the SEP-10 endpoints.
package httpapi

import (
	"encoding/json"
	"log/slog"
	"net/http"
)

// errorBody is the shape of every error response. It names the failure class
// and nothing else: no signature material, no internal state, no secret.
type errorBody struct {
	Error string `json:"error"`
}

// writeJSON writes a JSON response. A failure to encode is logged, not
// returned: the status line has already gone out and there is nothing useful
// left to tell the client.
func writeJSON(w http.ResponseWriter, logger *slog.Logger, status int, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		logger.Error("encoding response failed", "error", err)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"internal server error"}`))
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write(encoded); err != nil {
		logger.Warn("writing response failed", "error", err)
	}
}

// writeError writes an error response carrying only the failure class.
func writeError(w http.ResponseWriter, logger *slog.Logger, status int, message string) {
	writeJSON(w, logger, status, errorBody{Error: message})
}
