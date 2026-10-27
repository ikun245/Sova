package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"soc/agent/internal/app"
	"soc/agent/internal/domain"
)

type alertRepositoryStub struct {
	duplicate bool
}

func (alertRepositoryStub) CreateAlert(_ context.Context, alert domain.Alert) (domain.Alert, error) {
	return alert, nil
}

func (alertRepositoryStub) ListAlerts(context.Context, string, int) ([]domain.Alert, error) {
	return []domain.Alert{}, nil
}

func (s alertRepositoryStub) IngestAlert(_ context.Context, alert domain.Alert, _ domain.Task, _ []domain.Intent, _ domain.OutboxMessage) (domain.Alert, bool, error) {
	return alert, !s.duplicate, nil
}

func TestCreateAlertReturnsCreatedAndRequestID(t *testing.T) {
	handler := NewRouter(app.NewAlerts(alertRepositoryStub{}), func(context.Context) error { return nil })
	request := httptest.NewRequest(http.MethodPost, "/api/v1/alerts", strings.NewReader(`{"source":"waf","raw":{"event":"blocked"}}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusCreated {
		t.Fatalf("status = %d, want %d; body: %s", response.Code, http.StatusCreated, response.Body.String())
	}
	if response.Header().Get("X-Request-ID") == "" {
		t.Fatal("expected X-Request-ID response header")
	}
}

func TestCreateDuplicateAlertReturnsOK(t *testing.T) {
	handler := NewRouter(app.NewAlerts(alertRepositoryStub{duplicate: true}), func(context.Context) error { return nil })
	request := httptest.NewRequest(http.MethodPost, "/api/v1/alerts", strings.NewReader(`{"source":"waf","raw":{"event":"blocked"}}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; duplicates must not report 201", response.Code, http.StatusOK)
	}
}

func TestCreateAlertRejectsUnknownFields(t *testing.T) {
	handler := NewRouter(app.NewAlerts(alertRepositoryStub{}), func(context.Context) error { return nil })
	request := httptest.NewRequest(http.MethodPost, "/api/v1/alerts", strings.NewReader(`{"source":"waf","raw":{},"extra":true}`))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusBadRequest)
	}
}

func TestReadyzReportsDatabaseFailure(t *testing.T) {
	handler := NewRouter(app.NewAlerts(alertRepositoryStub{}), func(context.Context) error {
		return errors.New("test database error")
	})
	request := httptest.NewRequest(http.MethodGet, "/readyz", nil)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusServiceUnavailable)
	}
	if strings.Contains(response.Body.String(), "test database error") {
		t.Fatal("readiness response must not expose internal database errors")
	}
}
