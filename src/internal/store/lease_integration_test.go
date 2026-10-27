//go:build integration

package store

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"soc/agent/internal/domain"
)

// newLeaseTask creates a task with one pending intent and claims it, returning
// the task id and the claimed intent.
func newLeaseTask(t *testing.T, database *Postgres, worker string, lease time.Duration) (string, domain.Intent) {
	t.Helper()
	suffix := taskID(t)
	intentID := "lease-" + suffix
	task := newTestTask(t, database, domain.Intent{
		ID: intentID, Seq: 1, Kind: "agent_run",
		Payload: json.RawMessage(`{}`), Status: domain.IntentStatusPending,
	})
	intent, err := database.ClaimIntent(context.Background(), task.ID, worker, lease)
	if err != nil {
		t.Fatalf("ClaimIntent() error = %v", err)
	}
	return task.ID, intent
}

func TestRenewLeaseExtendsAndReportsSuccess(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()

	taskID, intent := newLeaseTask(t, database, "worker-a", 2*time.Second)

	var before time.Time
	if err := database.db.QueryRowContext(ctx,
		`SELECT lease_until FROM agent_tasks WHERE id = $1`, taskID).Scan(&before); err != nil {
		t.Fatalf("read initial lease: %v", err)
	}

	ok, err := database.RenewLease(ctx, intent.ID, "worker-a", time.Hour)
	if err != nil {
		t.Fatalf("RenewLease() error = %v", err)
	}
	if !ok {
		t.Fatal("RenewLease() = false, want true for the current owner")
	}

	var after time.Time
	if err := database.db.QueryRowContext(ctx,
		`SELECT lease_until FROM agent_tasks WHERE id = $1`, taskID).Scan(&after); err != nil {
		t.Fatalf("read renewed lease: %v", err)
	}
	if !after.After(before) {
		t.Fatalf("lease_until did not move forward: %s -> %s", before, after)
	}
	// The renewal must extend from now, not from the previous expiry, otherwise
	// repeated renewals could never outrun a short original lease.
	if time.Until(after) < 50*time.Minute {
		t.Fatalf("renewed lease expires too soon: %s", time.Until(after))
	}
}

func TestRenewLeaseRejectsAWorkerThatDoesNotOwnTheIntent(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()

	_, intent := newLeaseTask(t, database, "worker-a", time.Hour)

	ok, err := database.RenewLease(ctx, intent.ID, "worker-b", time.Hour)
	if err != nil {
		t.Fatalf("RenewLease() error = %v", err)
	}
	if ok {
		t.Fatal("a non-owner renewed the lease; that would let any worker keep a task alive")
	}

	state, err := database.DiagnoseLease(ctx, intent.ID, "worker-b")
	if err != nil {
		t.Fatalf("DiagnoseLease() error = %v", err)
	}
	if state != domain.LeaseClaimedByOther {
		t.Fatalf("state = %s, want %s", state, domain.LeaseClaimedByOther)
	}
}

func TestExpiredLeaseIsReclaimedByAnotherWorker(t *testing.T) {
	// This is the crash-recovery path: worker A dies mid-step, its lease lapses,
	// and worker B must be able to resume the work.
	database := openTestStore(t)
	ctx := context.Background()

	taskID, intent := newLeaseTask(t, database, "worker-a", time.Second)

	// Simulate the lapse instead of sleeping: waiting out a real lease would
	// make the test slow and flaky.
	if _, err := database.db.ExecContext(ctx,
		`UPDATE agent_tasks SET lease_until = now() - interval '1 second' WHERE id = $1`, taskID); err != nil {
		t.Fatalf("expire lease: %v", err)
	}

	ok, err := database.RenewLease(ctx, intent.ID, "worker-a", time.Hour)
	if err != nil {
		t.Fatalf("RenewLease() error = %v", err)
	}
	if ok {
		t.Fatal("an expired lease was renewed; the dead worker could reclaim work it lost")
	}

	recovered, err := database.RecoverExpiredLeases(ctx)
	if err != nil {
		t.Fatalf("RecoverExpiredLeases() error = %v", err)
	}
	if recovered < 1 {
		t.Fatalf("recovered = %d, want at least 1", recovered)
	}

	// The task lease must be cleared too, otherwise the audit trail still names
	// a worker that is gone and every later renewal reports contention.
	var owner *string
	if err := database.db.QueryRowContext(ctx,
		`SELECT lease_owner FROM agent_tasks WHERE id = $1`, taskID).Scan(&owner); err != nil {
		t.Fatalf("read lease owner: %v", err)
	}
	if owner != nil {
		t.Fatalf("lease_owner = %q after recovery, want NULL", *owner)
	}

	reclaimed, err := database.ClaimIntent(ctx, taskID, "worker-b", time.Hour)
	if err != nil {
		t.Fatalf("worker-b ClaimIntent() error = %v", err)
	}
	if reclaimed.ID != intent.ID {
		t.Fatalf("worker-b claimed %q, want %q", reclaimed.ID, intent.ID)
	}
}

func TestRenewLeaseIsAtomicUnderContention(t *testing.T) {
	// Renewal and reclaim must not both succeed. A read-then-write would leave a
	// window where both believe they won, and the target would be attacked twice.
	database := openTestStore(t)
	ctx := context.Background()

	taskID, intent := newLeaseTask(t, database, "worker-a", time.Second)
	if _, err := database.db.ExecContext(ctx,
		`UPDATE agent_tasks SET lease_until = now() - interval '1 second' WHERE id = $1`, taskID); err != nil {
		t.Fatalf("expire lease: %v", err)
	}

	const workers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	renewed := 0
	reclaimed := 0

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			// Half try to renew as the dead owner, half try to reclaim. Exactly
			// one side may win, and never both.
			if id%2 == 0 {
				ok, err := database.RenewLease(ctx, intent.ID, "worker-a", time.Hour)
				if err == nil && ok {
					mu.Lock()
					renewed++
					mu.Unlock()
				}
				return
			}
			if _, err := database.RecoverExpiredLeases(ctx); err == nil {
				mu.Lock()
				reclaimed++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()

	if renewed > 0 && reclaimed > 0 {
		t.Fatalf("both renewal (%d) and reclaim (%d) succeeded; the lease is not atomic", renewed, reclaimed)
	}
}

func TestDiagnoseLeaseExplainsEveryLoss(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()

	t.Run("unknown intent", func(t *testing.T) {
		state, err := database.DiagnoseLease(ctx, "does-not-exist", "worker-a")
		if err != nil {
			t.Fatalf("DiagnoseLease() error = %v", err)
		}
		if state != domain.LeaseIntentNotFound {
			t.Fatalf("state = %s, want %s", state, domain.LeaseIntentNotFound)
		}
	})

	t.Run("completed intent", func(t *testing.T) {
		_, intent := newLeaseTask(t, database, "worker-a", time.Hour)
		if err := database.CompleteIntent(ctx, intent.ID, "ref"); err != nil {
			t.Fatalf("CompleteIntent() error = %v", err)
		}
		state, err := database.DiagnoseLease(ctx, intent.ID, "worker-a")
		if err != nil {
			t.Fatalf("DiagnoseLease() error = %v", err)
		}
		if state != domain.LeaseIntentNotClaimed {
			t.Fatalf("state = %s, want %s", state, domain.LeaseIntentNotClaimed)
		}
	})

	t.Run("finished task", func(t *testing.T) {
		taskID, intent := newLeaseTask(t, database, "worker-a", time.Hour)
		if err := database.SetTaskStatus(ctx, taskID, domain.TaskStatusCancelled); err != nil {
			t.Fatalf("SetTaskStatus() error = %v", err)
		}
		state, err := database.DiagnoseLease(ctx, intent.ID, "worker-a")
		if err != nil {
			t.Fatalf("DiagnoseLease() error = %v", err)
		}
		if state != domain.LeaseTaskFinished {
			t.Fatalf("state = %s, want %s", state, domain.LeaseTaskFinished)
		}
	})

	t.Run("healthy lease", func(t *testing.T) {
		_, intent := newLeaseTask(t, database, "worker-a", time.Hour)
		state, err := database.DiagnoseLease(ctx, intent.ID, "worker-a")
		if err != nil {
			t.Fatalf("DiagnoseLease() error = %v", err)
		}
		if state != domain.LeaseOK {
			t.Fatalf("state = %s, want %s", state, domain.LeaseOK)
		}
		if state.Lost() {
			t.Fatal("LeaseOK reported as lost")
		}
	})
}

func TestRecoverExpiredLeasesLeavesTerminalTasksAlone(t *testing.T) {
	// Resurrecting an intent on a cancelled task would execute work a human
	// already stopped.
	database := openTestStore(t)
	ctx := context.Background()

	taskID, intent := newLeaseTask(t, database, "worker-a", time.Second)
	if _, err := database.db.ExecContext(ctx,
		`UPDATE agent_tasks SET lease_until = now() - interval '1 second' WHERE id = $1`, taskID); err != nil {
		t.Fatalf("expire lease: %v", err)
	}
	if err := database.SetTaskStatus(ctx, taskID, domain.TaskStatusCancelled); err != nil {
		t.Fatalf("SetTaskStatus() error = %v", err)
	}

	if _, err := database.RecoverExpiredLeases(ctx); err != nil {
		t.Fatalf("RecoverExpiredLeases() error = %v", err)
	}

	var status domain.IntentStatus
	if err := database.db.QueryRowContext(ctx,
		`SELECT status FROM task_intents WHERE id = $1`, intent.ID).Scan(&status); err != nil {
		t.Fatalf("read intent status: %v", err)
	}
	if status == domain.IntentStatusPending {
		t.Fatal("an intent on a cancelled task was returned to pending")
	}
}
