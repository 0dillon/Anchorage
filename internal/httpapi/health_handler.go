package httpapi

import (
	"log/slog"
	"net/http"
)

// healthResponse is the body of GET /health.
type healthResponse struct {
	Status   string `json:"status"`
	Database string `json:"database"`
}

// healthHandler reports process and database liveness. The database error is
// logged but never returned: it can name hosts and users.
func healthHandler(pinger Pinger, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := pinger.Ping(r.Context()); err != nil {
			logger.Error("health check failed", "error", err)
			writeJSON(w, logger, http.StatusServiceUnavailable,
				healthResponse{Status: "degraded", Database: "unavailable"})
			return
		}
		writeJSON(w, logger, http.StatusOK,
			healthResponse{Status: "ok", Database: "ok"})
	}
}
