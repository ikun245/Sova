package queue

import (
	"context"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/hibiken/asynq"

	"soc/agent/internal/domain"
	"soc/agent/internal/store"
)

// leaseRepo is a fake task repository that can be told to lose the lease after
// a number of renewals, so the heartbeat paths can be exercised without a
// database.
type leaseRepo struct {
	mu        sync.Mutex
	claimed   bool
	completed int
	renewals  int
	// loseAfter is how many successful renewals happen before the lease is
	// considered lost. Negative means never lose it.
	loseAfter int
	// renewErr, when set, is returned instead of a renewal result.
	renewErr error
}

func (r *leaseRepo) CreateTask(context.Context, domain.Task, []domain.Intent) (domain.Task, error) {
	return domain.Task{}, nil
}

func (r *leaseRepo) GetTask(context.Context, string) (domain.Task, error) {
	return domain.Task{ID: "task-1", Status: domain.TaskStatusRunning}, nil
}

func (r *leaseRepo) ClaimIntent(context.Context, string, string, time.Duration) (domain.Intent, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.claimed {
		return domain.Intent{}, store.ErrNoIntentReady
	}
	r.claimed = true
	return domain.Intent{ID: "intent-1", TaskID: "task-1", Seq: 1, Kind: "agent_run"}, nil
}

func (r *leaseRepo) RenewLease(context.Context, string, string, time.Duration) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.renewErr != nil {
		return false, r.renewErr
	}
	if r.loseAfter >= 0 && r.renewals >= r.loseAfter {
		return false, nil
	}
	r.renewals++
	return true, nil
}

func (r *leaseRepo) DiagnoseLease(context.Context, string, string) (domain.LeaseState, error) {
	return domain.LeaseClaimedByOther, nil
}

func (r *leaseRepo) CompleteIntent(context.Context, string, string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.completed++
	return nil
}

func (r *leaseRepo) FinishTaskIfDone(context.Context, string, domain.TaskStatus) (bool, error) {
	return true, nil
}

func (r *leaseRepo) SetTaskStatus(context.Context, string, domain.TaskStatus) error { return nil }

func (r *leaseRepo) SaveCheckpoint(context.Context, string, []byte) error { return nil }

func (r *leaseRepo) AppendTaskEvent(context.Context, domain.TaskEvent) error { return nil }

func (r *leaseRepo) RecoverExpiredLeases(context.Context) (int64, error) { return 0, nil }

func (r *leaseRepo) FinishIdleTasks(context.Context) (int64, error) { return 0, nil }

// slowExecutor blocks until released, so a test can hold an intent long enough
// for the heartbeat to run.
type slowExecutor struct {
	release chan struct{}
	ran     atomic.Bool
	ctxDone atomic.Bool
}

func (s *slowExecutor) Execute(ctx context.Context, _ domain.Task, _ domain.Intent) (ExecutionResult, error) {
	s.ran.Store(true)
	select {
	case <-s.release:
	case <-ctx.Done():
		s.ctxDone.Store(true)
	}
	return ExecutionResult{Summary: "done"}, nil
}

func newLeaseHandler(t *testing.T, repo *leaseRepo, executor Executor, lease time.Duration) *TriageHandler {
	t.Helper()
	handler := NewTriageHandler(repo, lease)
	handler.SetExecutor(executor)
	return handler
}

func leaseTask(t *testing.T) *asynq.Task {
	t.Helper()
	payload, err := json.Marshal(map[string]string{"task_id": "task-1"})
	if err != nil {
		t.Fatalf("marshal payload: %v", err)
	}
	return asynq.NewTask(TaskTypeTriage, payload)
}

func TestHandlerRenewsLeaseWhileExecuting(t *testing.T) {
	// Without renewal, an agent intent that takes longer than the lease is
	// declared dead while it is still working, and a second worker claims it.
	repo := &leaseRepo{loseAfter: -1}
	executor := &slowExecutor{release: make(chan struct{})}
	// A 30ms lease gives a 10ms heartbeat interval, so several renewals land
	// inside the test window without making the test slow.
	handler := newLeaseHandler(t, repo, executor, 30*time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- handler.Handle(context.Background(), leaseTask(t)) }()

	deadline := time.After(2 * time.Second)
	for {
		repo.mu.Lock()
		renewals := repo.renewals
		repo.mu.Unlock()
		if renewals >= 2 {
			break
		}
		select {
		case <-deadline:
			t.Fatalf("only %d renewals happened while the intent ran", renewals)
		case <-time.After(5 * time.Millisecond):
		}
	}

	close(executor.release)
	if err := <-done; err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if !executor.ran.Load() {
		t.Fatal("the executor never ran")
	}
	if repo.completed != 1 {
		t.Fatalf("completed = %d, want 1", repo.completed)
	}
}

func TestHandlerStopsAndWritesNothingWhenLeaseIsLost(t *testing.T) {
	// A lost lease means another worker owns the intent. Completing it here
	// would overwrite that worker's result, so the handler must return silently.
	repo := &leaseRepo{loseAfter: 0}
	executor := &slowExecutor{release: make(chan struct{})}
	handler := newLeaseHandler(t, repo, executor, 20*time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- handler.Handle(context.Background(), leaseTask(t)) }()

	// Wait for the heartbeat to cancel the work.
	deadline := time.After(2 * time.Second)
	for !executor.ctxDone.Load() {
		select {
		case <-deadline:
			t.Fatal("the execution context was never cancelled after the lease was lost")
		case <-time.After(5 * time.Millisecond):
		}
	}

	if err := <-done; err != nil {
		t.Fatalf("Handle() error = %v; losing a lease is contention, not a failure", err)
	}
	if repo.completed != 0 {
		t.Fatalf("completed = %d, want 0: the intent belongs to another worker now", repo.completed)
	}
}

func TestHandlerKeepsWorkingOnATransientRenewalError(t *testing.T) {
	// A database blip is not proof that the lease was taken. Aborting would
	// abandon a healthy run, so the heartbeat keeps trying.
	repo := &leaseRepo{loseAfter: -1, renewErr: errors.New("transient connection reset")}
	executor := &slowExecutor{release: make(chan struct{})}
	handler := newLeaseHandler(t, repo, executor, 20*time.Millisecond)

	done := make(chan error, 1)
	go func() { done <- handler.Handle(context.Background(), leaseTask(t)) }()

	time.Sleep(120 * time.Millisecond)
	close(executor.release)

	if err := <-done; err != nil {
		t.Fatalf("Handle() error = %v", err)
	}
	if repo.completed != 1 {
		t.Fatalf("completed = %d, want 1: a transient renewal error must not abandon the run", repo.completed)
	}
}

func TestHeartbeatIntervalLeavesRenewalMargin(t *testing.T) {
	// The interval must be a fraction of the lease, otherwise a single slow
	// renewal outlives the lease it was meant to extend.
	repo := &leaseRepo{loseAfter: -1}
	handler := NewTriageHandler(repo, 300*time.Millisecond)

	_, stop, _ := handler.heartbeat(context.Background(), "intent-1")
	time.Sleep(180 * time.Millisecond)
	stop()

	repo.mu.Lock()
	renewals := repo.renewals
	repo.mu.Unlock()
	if renewals < 1 {
		t.Fatalf("renewals = %d, want at least 1 within 180ms of a 300ms lease", renewals)
	}
}

func TestHeartbeatStopIsIdempotent(t *testing.T) {
	// The handler stops the heartbeat from both the success and error paths, so
	// a second stop must not panic on a closed channel.
	repo := &leaseRepo{loseAfter: -1}
	handler := NewTriageHandler(repo, time.Hour)

	_, stop, _ := handler.heartbeat(context.Background(), "intent-1")
	stop()
	stop()
}
