package api

import (
	"net/http"
	"strings"

	"soc/agent/internal/domain"
)

// findingHandlers exposes recorded findings so an operator can see the
// evidence a team run produced without reading the engagement's stdout log.
type findingHandlers struct {
	findings domain.FindingRepository
}

func (h findingHandlers) list(w http.ResponseWriter, r *http.Request) {
	taskID := strings.TrimSpace(r.URL.Query().Get("task_id"))
	if taskID == "" {
		writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
			OK: false, Code: domain.CodeInvalidArgument, Message: "task_id query parameter is required",
			Hint: "findings belong to a task; list the task first",
		})
		return
	}
	findings, err := h.findings.ListFindings(r.Context(), taskID)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not list findings")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "code": "ok", "items": findings, "total": len(findings)})
}
