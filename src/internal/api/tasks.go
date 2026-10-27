package api

import (
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"soc/agent/internal/domain"
	"soc/agent/internal/store"
)

// taskHandlers expose task state and lifecycle events over HTTP. These are the
// read paths that let an operator watch a team run without a terminal attached
// to it: the run itself is still driven by `soc team`/`soc hunt`, but its
// progress, parked approvals and findings become visible through the API.
type taskHandlers struct {
	tasks domain.TaskRepository
}

func (h taskHandlers) list(w http.ResponseWriter, r *http.Request) {
	filter := domain.TaskFilter{Status: domain.TaskStatus(r.URL.Query().Get("status"))}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			filter.Limit = parsed
		}
	}

	tasks, err := h.tasks.ListTasks(r.Context(), filter)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not list tasks")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "code": "ok", "items": tasks, "total": len(tasks)})
}

func (h taskHandlers) get(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, r, http.StatusBadRequest, string(domain.CodeInvalidArgument), "task id is required in the path")
		return
	}
	task, err := h.tasks.GetTask(r.Context(), id)
	if err != nil {
		if errors.Is(err, store.ErrTaskNotFound) {
			writeError(w, r, http.StatusNotFound, "not_found", "task not found")
			return
		}
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not load task")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "code": "ok", "task": task})
}

func (h taskHandlers) events(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, r, http.StatusBadRequest, string(domain.CodeInvalidArgument), "task id is required in the path")
		return
	}
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			limit = parsed
		}
	}
	events, err := h.tasks.ListTaskEvents(r.Context(), id, limit)
	if err != nil {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not list task events")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "code": "ok", "items": events, "total": len(events)})
}

// stream pushes new task events as Server-Sent Events, polling the store
// instead of subscribing to it: task_events has no publish/subscribe path, and
// polling a few times a second is cheap for the event volume one team run
// produces. `after` resumes a dropped connection without replaying everything.
func (h taskHandlers) stream(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, r, http.StatusBadRequest, string(domain.CodeInvalidArgument), "task id is required in the path")
		return
	}
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, r, http.StatusInternalServerError, "internal_error", "streaming is not supported by this server")
		return
	}

	after := 0
	if raw := r.URL.Query().Get("after"); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			after = parsed
		}
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	ctx := r.Context()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		events, err := h.tasks.ListTaskEvents(ctx, id, 200)
		if err == nil {
			for _, event := range events {
				if event.Seq <= after {
					continue
				}
				after = event.Seq
				fmt.Fprintf(w, "id: %d\nevent: %s\ndata: %s\n\n", event.Seq, event.Kind, event.Payload)
			}
			flusher.Flush()
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
