package domain

import (
	"context"
	"time"
)

// TaskFilter narrows ListTasks. The zero value lists every task for the
// (currently single) tenant, newest first.
type TaskFilter struct {
	// Status restricts to one status; empty means any.
	Status TaskStatus
	// Limit caps the result size; non-positive defaults to a safe cap.
	Limit int
}

type TaskRepository interface {
	CreateTask(ctx context.Context, task Task, intents []Intent) (Task, error)
	GetTask(ctx context.Context, taskID string) (Task, error)
	// ListTasks returns tasks matching the filter, most recently updated first.
	// It is what lets an operator see a team run from the API instead of only
	// from whatever is printed to a terminal.
	ListTasks(ctx context.Context, filter TaskFilter) ([]Task, error)
	// ClaimIntent atomically transitions a dependency-satisfied pending intent to
	// claimed, so two workers cannot execute the same step.
	ClaimIntent(ctx context.Context, taskID, workerID string, lease time.Duration) (Intent, error)
	// RenewLease extends the caller's lease on a claimed intent.
	//
	// A step that runs longer than the original lease would otherwise be
	// declared dead while it is still working, and a second worker would claim
	// the same intent: the same target attacked twice by two workers that do not
	// know about each other. Renewal is one conditional UPDATE, so it cannot race
	// with a reclaim.
	//
	// It reports false when the lease is no longer ours, which is not an error.
	// The caller must then stop *without* writing a result: another worker owns
	// the intent now, and completing it here would overwrite that worker's work.
	RenewLease(ctx context.Context, intentID, workerID string, lease time.Duration) (bool, error)
	// DiagnoseLease explains why a renewal failed, for logs and operator
	// messages. It must only be called after RenewLease reports false.
	DiagnoseLease(ctx context.Context, intentID, workerID string) (LeaseState, error)
	CompleteIntent(ctx context.Context, intentID, resultRef string) error
	// FinishTaskIfDone moves a task to a terminal status, but only when no
	// pending or claimed intents remain. It reports whether it transitioned.
	FinishTaskIfDone(ctx context.Context, taskID string, status TaskStatus) (bool, error)
	// SetTaskStatus moves a task to an explicit status regardless of remaining
	// intents. Used for waiting_review, where the work stops until a human
	// decides, and for failed, where continuing would only burn budget.
	SetTaskStatus(ctx context.Context, taskID string, status TaskStatus) error
	SaveCheckpoint(ctx context.Context, taskID string, checkpoint []byte) error
	AppendTaskEvent(ctx context.Context, event TaskEvent) error
	// ListTaskEvents returns events for a task in ascending sequence order.
	//
	// The team planner needs this to see what was already attempted and how each
	// attempt ended. Without it a re-planning round cannot tell "this direction
	// was exhausted with budget left over" from "this direction was never tried",
	// and would either repeat work or drop a viable route.
	ListTaskEvents(ctx context.Context, taskID string, limit int) ([]TaskEvent, error)
	// RecoverExpiredLeases returns intents whose worker lease expired to pending
	// so another worker can pick them up after a crash.
	RecoverExpiredLeases(ctx context.Context) (int64, error)
	// FinishIdleTasks closes tasks that are running but have no open intents,
	// which happens when a worker dies between the last completion and closure.
	FinishIdleTasks(ctx context.Context) (int64, error)
}
