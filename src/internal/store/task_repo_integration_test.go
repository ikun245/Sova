//go:build integration

package store

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"soc/agent/internal/domain"
)

func openTestStore(t *testing.T) *Postgres {
	t.Helper()
	dsn := os.Getenv("SOC_PG_DSN")
	if dsn == "" {
		dsn = "postgres://soc:soc-local-dev-only@127.0.0.1:5432/soc?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	database, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.Migrate(); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	return database
}

func newTestTask(t *testing.T, database *Postgres, intents ...domain.Intent) domain.Task {
	t.Helper()
	taskID := "task-" + time.Now().Format("20060102150405.000000000")
	task, err := database.CreateTask(context.Background(), domain.Task{
		ID:       taskID,
		TenantID: domain.LocalTenantID,
		Status:   domain.TaskStatusQueued,
	}, intents)
	if err != nil {
		t.Fatalf("CreateTask() error = %v", err)
	}
	t.Cleanup(func() {
		_, _ = database.db.ExecContext(context.Background(), `DELETE FROM agent_tasks WHERE id = $1`, taskID)
	})
	return task
}

func TestClaimIntentRespectsDependencies(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	suffix := taskID(t)
	firstID := "i1-" + suffix
	secondID := "i2-" + suffix
	task := newTestTask(t, database,
		domain.Intent{ID: firstID, Seq: 1, Kind: "normalize", Payload: json.RawMessage(`{}`), Status: domain.IntentStatusPending},
		domain.Intent{ID: secondID, Seq: 2, Kind: "analyze", Payload: json.RawMessage(`{}`), DependsOn: []string{firstID}, Status: domain.IntentStatusPending},
	)

	first, err := database.ClaimIntent(ctx, task.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatalf("first ClaimIntent() error = %v", err)
	}
	if first.Seq != 1 {
		t.Fatalf("first claimed seq = %d, want 1", first.Seq)
	}

	if _, err := database.ClaimIntent(ctx, task.ID, "worker-b", time.Minute); err != ErrNoIntentReady {
		t.Fatalf("second ClaimIntent() error = %v, want ErrNoIntentReady", err)
	}

	if err := database.CompleteIntent(ctx, first.ID, "ref-1"); err != nil {
		t.Fatalf("CompleteIntent() error = %v", err)
	}
	second, err := database.ClaimIntent(ctx, task.ID, "worker-b", time.Minute)
	if err != nil {
		t.Fatalf("ClaimIntent() after completion error = %v", err)
	}
	if second.Seq != 2 {
		t.Fatalf("second claimed seq = %d, want 2", second.Seq)
	}
}

func TestConcurrentClaimNeverDuplicatesAnIntent(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	task := newTestTask(t, database,
		domain.Intent{ID: "only-" + taskID(t), Seq: 1, Kind: "normalize", Payload: json.RawMessage(`{}`), Status: domain.IntentStatusPending},
	)

	const workers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(n int) {
			defer wg.Done()
			_, err := database.ClaimIntent(ctx, task.ID, "worker-"+string(rune('a'+n)), time.Minute)
			if err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			} else if err != ErrNoIntentReady {
				t.Errorf("unexpected ClaimIntent() error = %v", err)
			}
		}(i)
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("successful claims = %d, want exactly 1", successes)
	}
}

func TestSaveCheckpointIncrementsVersion(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	task := newTestTask(t, database)

	if err := database.SaveCheckpoint(ctx, task.ID, []byte(`{"step":1}`)); err != nil {
		t.Fatalf("SaveCheckpoint() error = %v", err)
	}
	saved, err := database.GetTask(ctx, task.ID)
	if err != nil {
		t.Fatalf("GetTask() error = %v", err)
	}
	if saved.CheckpointVersion != task.CheckpointVersion+1 {
		t.Fatalf("checkpoint version = %d, want %d", saved.CheckpointVersion, task.CheckpointVersion+1)
	}
}

func TestAppendTaskEventAssignsMonotonicSeq(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	task := newTestTask(t, database)

	for i := 0; i < 3; i++ {
		if err := database.AppendTaskEvent(ctx, domain.TaskEvent{
			TaskID:  task.ID,
			Kind:    "intent_completed",
			Payload: json.RawMessage(`{"ok":true}`),
		}); err != nil {
			t.Fatalf("AppendTaskEvent() error = %v", err)
		}
	}

	var count, maxSeq int
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*), max(seq) FROM task_events WHERE task_id = $1`, task.ID,
	).Scan(&count, &maxSeq); err != nil {
		t.Fatalf("query task events: %v", err)
	}
	if count != 3 || maxSeq != 3 {
		t.Fatalf("events = %d, max seq = %d; want 3 and 3", count, maxSeq)
	}
}

func TestCompleteIntentIsNotIdempotentAcrossWorkers(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	task := newTestTask(t, database,
		domain.Intent{ID: "only2-" + taskID(t), Seq: 1, Kind: "normalize", Payload: json.RawMessage(`{}`), Status: domain.IntentStatusPending},
	)
	claimed, err := database.ClaimIntent(ctx, task.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatalf("ClaimIntent() error = %v", err)
	}
	if err := database.CompleteIntent(ctx, claimed.ID, ""); err != nil {
		t.Fatalf("first CompleteIntent() error = %v", err)
	}
	if err := database.CompleteIntent(ctx, claimed.ID, ""); err != ErrUnexpectedStatus {
		t.Fatalf("second CompleteIntent() error = %v, want ErrUnexpectedStatus", err)
	}
}

func TestFinishTaskIfDoneWaitsForOpenIntents(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	suffix := taskID(t)
	firstID := "f1-" + suffix
	secondID := "f2-" + suffix
	task := newTestTask(t, database,
		domain.Intent{ID: firstID, Seq: 1, Kind: "normalize", Payload: json.RawMessage(`{}`), Status: domain.IntentStatusPending},
		domain.Intent{ID: secondID, Seq: 2, Kind: "analyze", Payload: json.RawMessage(`{}`), DependsOn: []string{firstID}, Status: domain.IntentStatusPending},
	)

	first, err := database.ClaimIntent(ctx, task.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatalf("ClaimIntent() error = %v", err)
	}
	if err := database.CompleteIntent(ctx, first.ID, ""); err != nil {
		t.Fatalf("CompleteIntent() error = %v", err)
	}

	// The second intent is still pending, so the task must not close yet.
	finished, err := database.FinishTaskIfDone(ctx, task.ID, domain.TaskStatusSucceeded)
	if err != nil {
		t.Fatalf("FinishTaskIfDone() error = %v", err)
	}
	if finished {
		t.Fatal("task with a pending intent must not be marked finished")
	}

	second, err := database.ClaimIntent(ctx, task.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatalf("second ClaimIntent() error = %v", err)
	}
	if err := database.CompleteIntent(ctx, second.ID, ""); err != nil {
		t.Fatalf("CompleteIntent() error = %v", err)
	}

	finished, err = database.FinishTaskIfDone(ctx, task.ID, domain.TaskStatusSucceeded)
	if err != nil {
		t.Fatalf("FinishTaskIfDone() error = %v", err)
	}
	if !finished {
		t.Fatal("task with no open intents should be marked finished")
	}

	stored, err := database.GetTask(ctx, task.ID)
	if err != nil {
		t.Fatalf("GetTask() error = %v", err)
	}
	if stored.Status != domain.TaskStatusSucceeded {
		t.Fatalf("status = %q, want %q", stored.Status, domain.TaskStatusSucceeded)
	}
}

func TestRecoverExpiredLeasesReturnsIntentToPending(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	task := newTestTask(t, database,
		domain.Intent{ID: "lease-" + taskID(t), Seq: 1, Kind: "normalize", Payload: json.RawMessage(`{}`), Status: domain.IntentStatusPending},
	)

	// A negative lease makes the claim expire immediately, simulating a crash.
	if _, err := database.ClaimIntent(ctx, task.ID, "crashed-worker", -time.Minute); err != nil {
		t.Fatalf("ClaimIntent() error = %v", err)
	}
	if _, err := database.RecoverExpiredLeases(ctx); err != nil {
		t.Fatalf("RecoverExpiredLeases() error = %v", err)
	}

	recovered, err := database.ClaimIntent(ctx, task.ID, "healthy-worker", time.Minute)
	if err != nil {
		t.Fatalf("ClaimIntent() after recovery error = %v", err)
	}
	if recovered.ClaimedBy != "healthy-worker" {
		t.Fatalf("claimed_by = %q, want healthy-worker", recovered.ClaimedBy)
	}
}

func TestFinishIdleTasksClosesOrphanedRunningTask(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	task := newTestTask(t, database,
		domain.Intent{ID: "idle-" + taskID(t), Seq: 1, Kind: "normalize", Payload: json.RawMessage(`{}`), Status: domain.IntentStatusPending},
	)

	claimed, err := database.ClaimIntent(ctx, task.ID, "worker-a", time.Minute)
	if err != nil {
		t.Fatalf("ClaimIntent() error = %v", err)
	}
	if err := database.CompleteIntent(ctx, claimed.ID, ""); err != nil {
		t.Fatalf("CompleteIntent() error = %v", err)
	}

	closed, err := database.FinishIdleTasks(ctx)
	if err != nil {
		t.Fatalf("FinishIdleTasks() error = %v", err)
	}
	if closed < 1 {
		t.Fatalf("closed = %d, want at least 1", closed)
	}

	stored, err := database.GetTask(ctx, task.ID)
	if err != nil {
		t.Fatalf("GetTask() error = %v", err)
	}
	if stored.Status != domain.TaskStatusSucceeded {
		t.Fatalf("status = %q, want %q", stored.Status, domain.TaskStatusSucceeded)
	}
}

func taskID(t *testing.T) string {
	t.Helper()
	return time.Now().Format("150405.000000000")
}
