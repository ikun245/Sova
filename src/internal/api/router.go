package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"soc/agent/internal/app"
	"soc/agent/internal/domain"
)

type healthCheck func(context.Context) error

// RouterDeps carries the optional repositories NewRouter wires routes for. A
// zero-value field disables the routes that need it, so a caller without
// red-team authorization or team runs configured still gets a working router.
type RouterDeps struct {
	Scopes   domain.ScopeRepository
	Tasks    domain.TaskRepository
	Findings domain.FindingRepository
}

// NewRouter wires the HTTP surface. deps is optional (0 or 1 values) so
// existing callers and tests keep working when a dependency is not in use.
func NewRouter(alerts *app.Alerts, checkDatabase healthCheck, deps ...RouterDeps) http.Handler {
	var dep RouterDeps
	if len(deps) > 0 {
		dep = deps[0]
	}

	mux := http.NewServeMux()
	handlers := alertHandlers{alerts: alerts}
	mux.HandleFunc("GET /healthz", healthz)
	mux.HandleFunc("GET /readyz", readyz(checkDatabase))
	mux.HandleFunc("POST /api/v1/alerts", handlers.create)
	mux.HandleFunc("GET /api/v1/alerts", handlers.list)

	if dep.Scopes != nil {
		scopeOps := scopeHandlers{scopes: dep.Scopes}
		mux.HandleFunc("POST /api/v1/scopes", scopeOps.create)
		mux.HandleFunc("GET /api/v1/scopes", scopeOps.list)
		mux.HandleFunc("DELETE /api/v1/scopes/{id}", scopeOps.revoke)
		mux.HandleFunc("POST /api/v1/approvals", scopeOps.requestApproval)
		mux.HandleFunc("GET /api/v1/approvals", scopeOps.listApprovals)
		mux.HandleFunc("POST /api/v1/approvals/{id}/decide", scopeOps.decideApproval)
	}

	if dep.Tasks != nil {
		taskOps := taskHandlers{tasks: dep.Tasks}
		mux.HandleFunc("GET /api/v1/tasks", taskOps.list)
		mux.HandleFunc("GET /api/v1/tasks/{id}", taskOps.get)
		mux.HandleFunc("GET /api/v1/tasks/{id}/events", taskOps.events)
		mux.HandleFunc("GET /api/v1/tasks/{id}/events/stream", taskOps.stream)
	}

	if dep.Findings != nil {
		findingOps := findingHandlers{findings: dep.Findings}
		mux.HandleFunc("GET /api/v1/findings", findingOps.list)
	}

	return requestID(mux)
}

func healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func readyz(check healthCheck) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
		defer cancel()
		if err := check(ctx); err != nil {
			slog.ErrorContext(ctx, "readiness check failed", "error", err, "request_id", w.Header().Get("X-Request-ID"))
			writeError(w, r, http.StatusServiceUnavailable, "not_ready", "database is unavailable")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	}
}

func requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := r.Header.Get("X-Request-ID")
		if requestID == "" {
			var value [16]byte
			if _, err := rand.Read(value[:]); err == nil {
				requestID = hex.EncodeToString(value[:])
			} else {
				requestID = "unavailable"
			}
		}
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
