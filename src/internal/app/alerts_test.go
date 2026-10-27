package app

import (
	"context"
	"encoding/json"
	"testing"

	"soc/agent/internal/domain"
)

type alertRepositoryStub struct {
	created   domain.Alert
	task      domain.Task
	intents   []domain.Intent
	message   domain.OutboxMessage
	duplicate bool
}

func (s *alertRepositoryStub) CreateAlert(_ context.Context, alert domain.Alert) (domain.Alert, error) {
	s.created = alert
	return alert, nil
}

func (*alertRepositoryStub) ListAlerts(context.Context, string, int) ([]domain.Alert, error) {
	return nil, nil
}

func (s *alertRepositoryStub) IngestAlert(_ context.Context, alert domain.Alert, task domain.Task, intents []domain.Intent, message domain.OutboxMessage) (domain.Alert, bool, error) {
	s.created = alert
	s.task = task
	s.intents = intents
	s.message = message
	return alert, !s.duplicate, nil
}

func TestCreateCanonicalizesJSONAndSetsLocalTenant(t *testing.T) {
	repository := &alertRepositoryStub{}
	service := NewAlerts(repository)

	alert, created, err := service.Create(context.Background(), "  waf ", json.RawMessage(`{"b":2,"a":1}`))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if !created {
		t.Fatal("Create() should report a newly created alert")
	}
	if alert.TenantID != domain.LocalTenantID {
		t.Fatalf("TenantID = %q, want %q", alert.TenantID, domain.LocalTenantID)
	}
	if got, want := string(alert.Raw), `{"a":1,"b":2}`; got != want {
		t.Fatalf("Raw = %s, want %s", got, want)
	}
	if alert.DedupKey == "" || alert.ID == "" {
		t.Fatal("Create() should populate id and dedup key")
	}
	if repository.created.Source != "waf" {
		t.Fatalf("stored Source = %q, want trimmed source", repository.created.Source)
	}
}

func TestCreateEnqueuesTriageWorkInSameCommit(t *testing.T) {
	repository := &alertRepositoryStub{}
	service := NewAlerts(repository)

	alert, _, err := service.Create(context.Background(), "waf", json.RawMessage(`{"event":"blocked"}`))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if repository.task.TenantID != domain.LocalTenantID {
		t.Fatalf("task TenantID = %q, want %q", repository.task.TenantID, domain.LocalTenantID)
	}
	if repository.task.CaseID != alert.ID {
		t.Fatalf("task CaseID = %q, want alert id %q", repository.task.CaseID, alert.ID)
	}
	if len(repository.intents) != 1 || repository.intents[0].Status != domain.IntentStatusPending {
		t.Fatalf("intents = %+v, want one pending intent", repository.intents)
	}
	if repository.intents[0].TaskID != repository.task.ID {
		t.Fatal("intent must reference the created task")
	}
	if repository.message.Topic != "task.queued" {
		t.Fatalf("outbox topic = %q, want task.queued", repository.message.Topic)
	}
	var payload map[string]string
	if err := json.Unmarshal(repository.message.Payload, &payload); err != nil {
		t.Fatalf("decode outbox payload: %v", err)
	}
	if payload["task_id"] != repository.task.ID {
		t.Fatalf("outbox task_id = %q, want %q", payload["task_id"], repository.task.ID)
	}
}

func TestCreateReportsDuplicateWithoutNewWork(t *testing.T) {
	repository := &alertRepositoryStub{duplicate: true}
	service := NewAlerts(repository)

	_, created, err := service.Create(context.Background(), "waf", json.RawMessage(`{"event":"blocked"}`))
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if created {
		t.Fatal("duplicate alert must not be reported as created")
	}
}

func TestCreateRejectsInvalidJSON(t *testing.T) {
	service := NewAlerts(&alertRepositoryStub{})
	if _, _, err := service.Create(context.Background(), "waf", json.RawMessage(`{"broken"}`)); err == nil {
		t.Fatal("expected invalid JSON to be rejected")
	}
}
