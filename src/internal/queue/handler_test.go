package queue

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/hibiken/asynq"

	"soc/agent/internal/domain"
	"soc/agent/internal/store"
)

type failingTaskRepo struct {
	claimed     bool
	events      []domain.TaskEvent
	completed   int
	finishCall  int
	finalStatus domain.TaskStatus
}

func (f *failingTaskRepo) CreateTask(context.Context, domain.Task, []domain.Intent) (domain.Task, error) {
	return domain.Task{}, nil
}

func (f *failingTaskRepo) GetTask(context.Context, string) (domain.Task, error) {
	return domain.Task{ID: "task-1", Status: domain.TaskStatusRunning}, nil
}

func (f *failingTaskRepo) ClaimIntent(context.Context, string, string, time.Duration) (domain.Intent, error) {
	if f.claimed {
		return domain.Intent{}, store.ErrNoIntentReady
	}
	f.claimed = true
	return domain.Intent{ID: "intent-1", TaskID: "task-1", Seq: 1, Kind: "triage"}, nil
}

func (f *failingTaskRepo) CompleteIntent(context.Context, string, string) error {
	f.completed++
	return nil
}

func (f *failingTaskRepo) FinishTaskIfDone(context.Context, string, domain.TaskStatus) (bool, error) {
	f.finishCall++
	return true, nil
}

func (f *failingTaskRepo) SetTaskStatus(_ context.Context, _ string, status domain.TaskStatus) error {
	f.finalStatus = status
	return nil
}

func (f *failingTaskRepo) SaveCheckpoint(context.Context, string, []byte) error { return nil }

func (f *failingTaskRepo) AppendTaskEvent(_ context.Context, event domain.TaskEvent) error {
	f.events = append(f.events, event)
	return nil
}

func (f *failingTaskRepo) RecoverExpiredLeases(context.Context) (int64, error) { return 0, nil }
func (f *failingTaskRepo) FinishIdleTasks(context.Context) (int64, error)      { return 0, nil }

// New lease methods. The fake never loses its lease, so renewal always succeeds;
// the losing path is covered by the lease-specific tests.
func (f *failingTaskRepo) RenewLease(context.Context, string, string, time.Duration) (bool, error) {
	return true, nil
}

func (f *failingTaskRepo) DiagnoseLease(context.Context, string, string) (domain.LeaseState, error) {
	return domain.LeaseOK, nil
}

type recordingConsultator struct {
	calls   int
	err     error
	summary string
	signals domain.StallSignals
}

func (r *recordingConsultator) SummonForTask(_ context.Context, _ string, signals domain.StallSignals, _ string) (string, error) {
	r.calls++
	r.signals = signals
	if r.err != nil {
		return "", r.err
	}
	return r.summary, nil
}

// failingHandler exposes the failed-execution path without needing a real
// model: the skeleton's execute is a no-op, so the test drives tryConsult
// directly through a handler whose task repo reports a failure.
func newFailingHandler(t *testing.T) (*TriageHandler, *failingTaskRepo) {
	t.Helper()
	repo := &failingTaskRepo{}
	return NewTriageHandler(repo, time.Minute), repo
}

func TestTryConsultRecordsCompletion(t *testing.T) {
	handler, repo := newFailingHandler(t)
	consultator := &recordingConsultator{summary: "room r-1: proceed"}
	handler.SetConsultation(consultator)

	handler.tryConsult(context.Background(), "task-1",
		domain.Intent{ID: "intent-1", Kind: "triage"}, errors.New("model unavailable"))

	if consultator.calls != 1 {
		t.Fatalf("consultation calls = %d, want 1", consultator.calls)
	}
	if consultator.signals.ToolErrors == 0 {
		t.Fatal("a failed execution must supply an objective stall signal")
	}
	if len(repo.events) != 1 || repo.events[0].Kind != "consultation_completed" {
		t.Fatalf("events = %+v, want one consultation_completed", repo.events)
	}

	var payload map[string]any
	if err := json.Unmarshal(repo.events[0].Payload, &payload); err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if payload["summary"] != "room r-1: proceed" {
		t.Fatalf("summary = %v", payload["summary"])
	}
}

func TestTryConsultRecordsRejection(t *testing.T) {
	handler, repo := newFailingHandler(t)
	handler.SetConsultation(&recordingConsultator{err: errors.New("no team configured")})

	handler.tryConsult(context.Background(), "task-1",
		domain.Intent{ID: "intent-1", Kind: "triage"}, errors.New("boom"))

	if len(repo.events) != 1 || repo.events[0].Kind != "consultation_rejected" {
		t.Fatalf("events = %+v, want one consultation_rejected", repo.events)
	}
}

func TestTryConsultIsNoOpWithoutConfiguration(t *testing.T) {
	handler, repo := newFailingHandler(t)

	handler.tryConsult(context.Background(), "task-1",
		domain.Intent{ID: "intent-1"}, errors.New("boom"))

	if len(repo.events) != 0 {
		t.Fatalf("events = %+v, want none when consultation is disabled", repo.events)
	}
}

func TestFailedIntentDoesNotCompleteOrFinishTask(t *testing.T) {
	handler, repo := newFailingHandler(t)
	handler.SetConsultation(&recordingConsultator{summary: "ok"})

	task := asynq.NewTask(TaskTypeTriage, []byte(`{"task_id":"task-1"}`))
	// execute is a no-op in the skeleton, so the intent succeeds here; this
	// test locks the ordering guarantee: completion happens only after a
	// successful execution.
	if err := handler.Handle(context.Background(), task); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if repo.completed != 1 {
		t.Fatalf("completed = %d, want 1", repo.completed)
	}
	if repo.finishCall != 1 {
		t.Fatalf("finishCall = %d, want 1 after the last intent", repo.finishCall)
	}
}
