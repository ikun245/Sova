package queue

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/hibiken/asynq"

	"soc/agent/internal/domain"
	"soc/agent/internal/store"
)

// scriptedRepo serves a fixed number of intents so tests can assert how many
// steps the handler consumes before stopping.
type scriptedRepo struct {
	remaining   int
	completed   int
	events      []domain.TaskEvent
	finalStatus domain.TaskStatus
	checkpoints int
}

func (s *scriptedRepo) CreateTask(context.Context, domain.Task, []domain.Intent) (domain.Task, error) {
	return domain.Task{}, nil
}

func (s *scriptedRepo) GetTask(context.Context, string) (domain.Task, error) {
	return domain.Task{ID: "task-1", Status: domain.TaskStatusRunning}, nil
}

func (s *scriptedRepo) ClaimIntent(context.Context, string, string, time.Duration) (domain.Intent, error) {
	if s.remaining <= 0 {
		return domain.Intent{}, store.ErrNoIntentReady
	}
	s.remaining--
	return domain.Intent{ID: "intent", TaskID: "task-1", Seq: 1, Kind: "triage", Payload: json.RawMessage(`{}`)}, nil
}

func (s *scriptedRepo) CompleteIntent(context.Context, string, string) error {
	s.completed++
	return nil
}

func (s *scriptedRepo) FinishTaskIfDone(context.Context, string, domain.TaskStatus) (bool, error) {
	return true, nil
}

func (s *scriptedRepo) SetTaskStatus(_ context.Context, _ string, status domain.TaskStatus) error {
	s.finalStatus = status
	return nil
}

func (s *scriptedRepo) SaveCheckpoint(context.Context, string, []byte) error {
	s.checkpoints++
	return nil
}

func (s *scriptedRepo) AppendTaskEvent(_ context.Context, event domain.TaskEvent) error {
	s.events = append(s.events, event)
	return nil
}

func (s *scriptedRepo) RecoverExpiredLeases(context.Context) (int64, error) { return 0, nil }
func (s *scriptedRepo) FinishIdleTasks(context.Context) (int64, error)      { return 0, nil }

func (s *scriptedRepo) RenewLease(context.Context, string, string, time.Duration) (bool, error) {
	return true, nil
}

func (s *scriptedRepo) DiagnoseLease(context.Context, string, string) (domain.LeaseState, error) {
	return domain.LeaseOK, nil
}

type stubExecutor struct {
	result ExecutionResult
	err    error
	calls  int
}

func (s *stubExecutor) Execute(context.Context, domain.Task, domain.Intent) (ExecutionResult, error) {
	s.calls++
	return s.result, s.err
}

func triageTask() *asynq.Task {
	return asynq.NewTask(TaskTypeTriage, []byte(`{"task_id":"task-1"}`))
}

func TestNeedsReviewStopsTheLoop(t *testing.T) {
	repo := &scriptedRepo{remaining: 3}
	handler := NewTriageHandler(repo, time.Minute)
	handler.SetExecutor(&stubExecutor{result: ExecutionResult{
		Kind:        "triage",
		NeedsReview: true,
		ReviewWhy:   []string{"confidence 0.40 is below the 0.75 floor"},
		Verdict:     &Verdict{Verdict: VerdictSuspicious, Severity: SeverityLow, Confidence: 0.4},
	}})

	if err := handler.Handle(context.Background(), triageTask()); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}

	if repo.completed != 1 {
		t.Fatalf("completed = %d, want exactly 1 step before parking for review", repo.completed)
	}
	if repo.finalStatus != domain.TaskStatusWaitingReview {
		t.Fatalf("status = %q, want waiting_review", repo.finalStatus)
	}

	var found bool
	for _, event := range repo.events {
		if event.Kind == "task_waiting_review" {
			found = true
			var payload map[string]any
			if err := json.Unmarshal(event.Payload, &payload); err != nil {
				t.Fatalf("decode event: %v", err)
			}
			if _, ok := payload["reasons"]; !ok {
				t.Fatal("the review event must record why a human is needed")
			}
		}
	}
	if !found {
		t.Fatal("expected a task_waiting_review event")
	}
	if repo.checkpoints != 1 {
		t.Fatalf("checkpoints = %d, want the verdict saved for review", repo.checkpoints)
	}
}

func TestConfidentVerdictCompletesAndFinishes(t *testing.T) {
	repo := &scriptedRepo{remaining: 2}
	handler := NewTriageHandler(repo, time.Minute)
	handler.SetExecutor(&stubExecutor{result: ExecutionResult{
		Kind:    "triage",
		Verdict: &Verdict{Verdict: VerdictFalsePositive, Severity: SeverityLow, Confidence: 0.95},
	}})

	if err := handler.Handle(context.Background(), triageTask()); err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if repo.completed != 2 {
		t.Fatalf("completed = %d, want both intents drained", repo.completed)
	}
	if repo.finalStatus == domain.TaskStatusWaitingReview {
		t.Fatal("a confident verdict must not park the task for review")
	}
}

func TestExecutorErrorTriggersConsultation(t *testing.T) {
	repo := &scriptedRepo{remaining: 1}
	handler := NewTriageHandler(repo, time.Minute)
	handler.SetExecutor(&stubExecutor{err: errBoom})
	consultator := &recordingConsultator{summary: "room 1: escalate"}
	handler.SetConsultation(consultator)

	if err := handler.Handle(context.Background(), triageTask()); err == nil {
		t.Fatal("a failed execution must surface as an error so asynq retries")
	}
	if consultator.calls != 1 {
		t.Fatalf("consultation calls = %d, want 1", consultator.calls)
	}
	if repo.completed != 0 {
		t.Fatal("a failed intent must not be marked complete")
	}
}

var errBoom = &boomError{}

type boomError struct{}

func (*boomError) Error() string { return "boom" }
