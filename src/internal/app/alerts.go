package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"soc/agent/internal/domain"
)

const maxAlertListSize = 100

var ErrInvalidAlert = errors.New("invalid alert")

type AlertRepository interface {
	domain.AlertRepository
	domain.AlertIngest
}

type Alerts struct {
	repository AlertRepository
}

func NewAlerts(repository AlertRepository) *Alerts {
	return &Alerts{repository: repository}
}

func (s *Alerts) Create(ctx context.Context, source string, raw json.RawMessage) (domain.Alert, bool, error) {
	source = strings.TrimSpace(source)
	if source == "" || len(source) > 128 {
		return domain.Alert{}, false, fmt.Errorf("%w: source is required and must be at most 128 characters", ErrInvalidAlert)
	}
	canonical, err := canonicalJSON(raw)
	if err != nil {
		return domain.Alert{}, false, fmt.Errorf("%w: raw must be valid JSON", ErrInvalidAlert)
	}

	alertID, err := newID()
	if err != nil {
		return domain.Alert{}, false, fmt.Errorf("generate alert id: %w", err)
	}
	taskID, err := newID()
	if err != nil {
		return domain.Alert{}, false, fmt.Errorf("generate task id: %w", err)
	}
	intentID, err := newID()
	if err != nil {
		return domain.Alert{}, false, fmt.Errorf("generate intent id: %w", err)
	}

	dedup := sha256.Sum256(append(append([]byte(source), 0), canonical...))

	alert := domain.Alert{
		ID:       alertID,
		TenantID: domain.LocalTenantID,
		Source:   source,
		Raw:      canonical,
		DedupKey: hex.EncodeToString(dedup[:]),
		Status:   domain.AlertStatusReceived,
	}
	task := domain.Task{
		ID:                taskID,
		TenantID:          domain.LocalTenantID,
		CaseID:            alertID,
		Status:            domain.TaskStatusQueued,
		CheckpointVersion: 1,
	}
	intents := []domain.Intent{{
		ID:      intentID,
		TaskID:  taskID,
		Seq:     1,
		Kind:    "triage",
		Payload: canonical,
		Status:  domain.IntentStatusPending,
	}}
	message, err := json.Marshal(map[string]string{"task_id": taskID, "alert_id": alertID})
	if err != nil {
		return domain.Alert{}, false, fmt.Errorf("encode outbox payload: %w", err)
	}

	return s.repository.IngestAlert(ctx, alert, task, intents, domain.OutboxMessage{
		Topic:   "task.queued",
		Payload: message,
	})
}

func (s *Alerts) List(ctx context.Context, tenantID string) ([]domain.Alert, error) {
	return s.repository.ListAlerts(ctx, tenantID, maxAlertListSize)
}

func canonicalJSON(raw json.RawMessage) (json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return nil, errors.New("multiple JSON values")
	}
	return json.Marshal(value)
}

func newID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
