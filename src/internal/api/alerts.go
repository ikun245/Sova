package api

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"soc/agent/internal/app"
	"soc/agent/internal/domain"
)

const maxAlertRequestBytes = 1 << 20

type alertHandlers struct {
	alerts *app.Alerts
}

type createAlertRequest struct {
	Source string          `json:"source"`
	Raw    json.RawMessage `json:"raw"`
}

func (h alertHandlers) create(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxAlertRequestBytes)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var request createAlertRequest
	if err := decoder.Decode(&request); err != nil {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "request body must be valid JSON with source and raw fields")
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeError(w, r, http.StatusBadRequest, "invalid_request", "request body must contain exactly one JSON value")
		return
	}

	alert, created, err := h.alerts.Create(r.Context(), request.Source, request.Raw)
	if errors.Is(err, app.ErrInvalidAlert) {
		writeError(w, r, http.StatusBadRequest, "invalid_alert", err.Error())
		return
	}
	if err != nil {
		slog.ErrorContext(r.Context(), "create alert failed", "error", err, "request_id", w.Header().Get("X-Request-ID"))
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not store alert")
		return
	}
	if !created {
		// A duplicate is not a new event; 200 distinguishes it from 201.
		writeJSON(w, http.StatusOK, alert)
		return
	}
	writeJSON(w, http.StatusCreated, alert)
}

func (h alertHandlers) list(w http.ResponseWriter, r *http.Request) {
	alerts, err := h.alerts.List(r.Context(), domain.LocalTenantID)
	if err != nil {
		slog.ErrorContext(r.Context(), "list alerts failed", "error", err, "request_id", w.Header().Get("X-Request-ID"))
		writeError(w, r, http.StatusInternalServerError, "internal_error", "could not list alerts")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"items": alerts})
}
