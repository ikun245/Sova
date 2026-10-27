//go:build integration

package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"soc/agent/internal/domain"
)

func TestSetTaskStatusReleasesLease(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	task := newTestTask(t, database,
		domain.Intent{ID: "status-" + taskID(t), Seq: 1, Kind: "triage",
			Payload: json.RawMessage(`{}`), Status: domain.IntentStatusPending},
	)

	// Claiming sets a lease; parking the task for review must clear it so a
	// stale lease cannot make the task look alive.
	if _, err := database.ClaimIntent(ctx, task.ID, "worker-a", time.Minute); err != nil {
		t.Fatalf("ClaimIntent() error = %v", err)
	}
	stored, err := database.GetTask(ctx, task.ID)
	if err != nil {
		t.Fatalf("GetTask() error = %v", err)
	}
	if stored.Status != domain.TaskStatusRunning {
		t.Fatalf("status = %q, want running after claim", stored.Status)
	}

	if err := database.SetTaskStatus(ctx, task.ID, domain.TaskStatusWaitingReview); err != nil {
		t.Fatalf("SetTaskStatus() error = %v", err)
	}

	stored, err = database.GetTask(ctx, task.ID)
	if err != nil {
		t.Fatalf("GetTask() error = %v", err)
	}
	if stored.Status != domain.TaskStatusWaitingReview {
		t.Fatalf("status = %q, want waiting_review", stored.Status)
	}
	if stored.LeaseUntil != nil {
		t.Fatal("parking a task must release its lease")
	}
}

func TestSetTaskStatusRejectsUnknownTask(t *testing.T) {
	database := openTestStore(t)
	err := database.SetTaskStatus(context.Background(), "does-not-exist", domain.TaskStatusFailed)
	if err != ErrTaskNotFound {
		t.Fatalf("error = %v, want ErrTaskNotFound", err)
	}
}
