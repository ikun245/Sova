package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"soc/agent/internal/domain"
)

var (
	ErrTaskNotFound     = errors.New("task not found")
	ErrNoIntentReady    = errors.New("no claimable intent")
	ErrLeaseNotHeld     = errors.New("task lease is not held by this worker")
	ErrUnexpectedStatus = errors.New("task is not in the expected status")
)

func (p *Postgres) CreateTask(ctx context.Context, task domain.Task, intents []domain.Intent) (domain.Task, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Task{}, fmt.Errorf("begin task transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	err = tx.QueryRowContext(ctx, `
		INSERT INTO agent_tasks (id, tenant_id, case_id, status, checkpoint, checkpoint_version)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6)
		RETURNING id, tenant_id, COALESCE(case_id, ''), status, COALESCE(checkpoint, '{}'::jsonb), checkpoint_version, attempt, created_at, updated_at`,
		task.ID, task.TenantID, task.CaseID, task.Status, nullableJSON(task.Checkpoint), task.CheckpointVersion,
	).Scan(&task.ID, &task.TenantID, &task.CaseID, &task.Status, &task.Checkpoint,
		&task.CheckpointVersion, &task.Attempt, &task.CreatedAt, &task.UpdatedAt)
	if err != nil {
		return domain.Task{}, fmt.Errorf("insert task: %w", err)
	}

	for _, intent := range intents {
		// json.Marshal(nil slice) yields `null`, which is a JSON scalar; the
		// dependency query uses jsonb_array_elements_text and needs an array.
		dependsOn := intent.DependsOn
		if dependsOn == nil {
			dependsOn = []string{}
		}
		encodedDependsOn, err := json.Marshal(dependsOn)
		if err != nil {
			return domain.Task{}, fmt.Errorf("encode intent dependencies: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO task_intents (id, task_id, seq, kind, payload, depends_on, status)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			intent.ID, task.ID, intent.Seq, intent.Kind, []byte(intent.Payload), encodedDependsOn, intent.Status,
		); err != nil {
			return domain.Task{}, fmt.Errorf("insert intent %d: %w", intent.Seq, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return domain.Task{}, fmt.Errorf("commit task transaction: %w", err)
	}
	return task, nil
}

func (p *Postgres) GetTask(ctx context.Context, taskID string) (domain.Task, error) {
	var task domain.Task
	err := p.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, COALESCE(case_id, ''), status, COALESCE(checkpoint, '{}'::jsonb), checkpoint_version, attempt, created_at, updated_at
		FROM agent_tasks WHERE id = $1`, taskID,
	).Scan(&task.ID, &task.TenantID, &task.CaseID, &task.Status, &task.Checkpoint,
		&task.CheckpointVersion, &task.Attempt, &task.CreatedAt, &task.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Task{}, ErrTaskNotFound
	}
	if err != nil {
		return domain.Task{}, fmt.Errorf("get task: %w", err)
	}
	return task, nil
}

// ListTasks reports tasks newest-updated-first, optionally restricted to one
// status. It is the read path the API uses so a team run is visible without a
// direct database query.
func (p *Postgres) ListTasks(ctx context.Context, filter domain.TaskFilter) ([]domain.Task, error) {
	limit := filter.Limit
	if limit <= 0 {
		limit = 100
	}
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, tenant_id, COALESCE(case_id, ''), status, COALESCE(checkpoint, '{}'::jsonb), checkpoint_version, attempt, created_at, updated_at
		FROM agent_tasks
		WHERE $1 = '' OR status = $1
		ORDER BY updated_at DESC
		LIMIT $2`, string(filter.Status), limit)
	if err != nil {
		return nil, fmt.Errorf("list tasks: %w", err)
	}
	defer rows.Close()

	out := make([]domain.Task, 0, limit)
	for rows.Next() {
		var task domain.Task
		if err := rows.Scan(&task.ID, &task.TenantID, &task.CaseID, &task.Status, &task.Checkpoint,
			&task.CheckpointVersion, &task.Attempt, &task.CreatedAt, &task.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan task: %w", err)
		}
		out = append(out, task)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list tasks: %w", err)
	}
	return out, nil
}

// ClaimIntent selects the lowest-sequence pending intent whose dependencies are
// all completed, then marks it claimed. FOR UPDATE SKIP LOCKED keeps concurrent
// workers from blocking on or duplicating the same row.
func (p *Postgres) ClaimIntent(ctx context.Context, taskID, workerID string, lease time.Duration) (domain.Intent, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Intent{}, fmt.Errorf("begin claim transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var intent domain.Intent
	var payload, dependsOn []byte
	err = tx.QueryRowContext(ctx, `
		SELECT ti.id, ti.task_id, ti.seq, ti.kind, ti.payload, ti.depends_on, ti.status,
		       COALESCE(ti.claimed_by, ''), COALESCE(ti.result_ref, '')
		FROM task_intents AS ti
		WHERE ti.task_id = $1
		  AND ti.status = 'pending'
		  AND NOT EXISTS (
		      SELECT 1
		      FROM jsonb_array_elements_text(ti.depends_on) AS dep_id(value)
		      LEFT JOIN task_intents AS dep
		             ON dep.id = dep_id.value AND dep.task_id = ti.task_id
		      WHERE dep.id IS NULL OR dep.status <> 'completed'
		  )
		ORDER BY ti.seq
		LIMIT 1
		FOR UPDATE OF ti SKIP LOCKED`, taskID,
	).Scan(&intent.ID, &intent.TaskID, &intent.Seq, &intent.Kind, &payload, &dependsOn,
		&intent.Status, &intent.ClaimedBy, &intent.ResultRef)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Intent{}, ErrNoIntentReady
	}
	if err != nil {
		return domain.Intent{}, fmt.Errorf("select claimable intent: %w", err)
	}

	// Decode before mutating anything so a malformed payload rolls back cleanly.
	if err := json.Unmarshal(payload, &intent.Payload); err != nil {
		return domain.Intent{}, fmt.Errorf("decode intent payload: %w", err)
	}
	if err := json.Unmarshal(dependsOn, &intent.DependsOn); err != nil {
		return domain.Intent{}, fmt.Errorf("decode intent dependencies: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE task_intents SET status = 'claimed', claimed_by = $2 WHERE id = $1`, intent.ID, workerID,
	); err != nil {
		return domain.Intent{}, fmt.Errorf("claim intent: %w", err)
	}

	leaseUntil := time.Now().Add(lease)
	if _, err := tx.ExecContext(ctx, `
		UPDATE agent_tasks
		SET status = 'running', lease_owner = $2, lease_until = $3, attempt = attempt + 1, updated_at = now()
		WHERE id = $1`, taskID, workerID, leaseUntil,
	); err != nil {
		return domain.Intent{}, fmt.Errorf("renew task lease: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return domain.Intent{}, fmt.Errorf("commit claim transaction: %w", err)
	}

	intent.Status = domain.IntentStatusClaimed
	intent.ClaimedBy = workerID
	return intent, nil
}

// RenewLease extends the caller's lease on a claimed intent, but only if the
// caller still owns both the intent and the task, and the lease has not already
// lapsed.
//
// A single conditional UPDATE with RETURNING is what makes this safe: if the
// intent was returned to pending (or claimed by another worker) between the
// caller's last check and now, no row matches and the caller learns it lost the
// lease. A read-then-write would leave a window in which the reclaim and the
// renewal both believe they won.
//
// The `lease_until > now()` condition is the important one. Expiry is the
// system's decision that this worker is gone; letting the worker extend an
// expired lease would let a process that was suspended for ten minutes resume
// with stale assumptions and veto that decision. A worker either renews before
// expiry or stops, which keeps recovery deterministic.
//
// Renewal is idempotent: calling it twice inside one lease period has the same
// effect as calling it once.
func (p *Postgres) RenewLease(ctx context.Context, intentID, workerID string, lease time.Duration) (bool, error) {
	if strings.TrimSpace(intentID) == "" || strings.TrimSpace(workerID) == "" {
		return false, fmt.Errorf("renew lease: intent id and worker id are required")
	}
	if lease <= 0 {
		return false, fmt.Errorf("renew lease: duration must be positive, got %s", lease)
	}

	var leaseUntil time.Time
	// make_interval keeps the duration a bound parameter; building the interval
	// as a string would put a number into SQL text for no benefit.
	err := p.db.QueryRowContext(ctx, `
		UPDATE agent_tasks AS t
		SET lease_until = now() + make_interval(secs => $3), updated_at = now()
		FROM task_intents AS ti
		WHERE ti.id = $1
		  AND ti.task_id = t.id
		  AND ti.status = 'claimed'
		  AND ti.claimed_by = $2
		  AND t.lease_owner = $2
		  AND t.status IN ('queued', 'running')
		  AND t.lease_until IS NOT NULL
		  AND t.lease_until > now()
		RETURNING t.lease_until`,
		intentID, workerID, lease.Seconds(),
	).Scan(&leaseUntil)
	if errors.Is(err, sql.ErrNoRows) {
		// Losing the lease is contention, not a failure: the caller stops and a
		// different worker continues. Reporting an error here would turn a
		// healthy handoff into a retry storm.
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("renew intent lease: %w", err)
	}
	return true, nil
}

// DiagnoseLease explains a failed renewal. It is a separate read so the hot
// path stays one statement, and it is only called when renewal already failed.
func (p *Postgres) DiagnoseLease(ctx context.Context, intentID, workerID string) (domain.LeaseState, error) {
	var claimedBy, status, taskStatus, taskOwner string
	var ownerKnown, leaseAlive bool
	err := p.db.QueryRowContext(ctx, `
		SELECT ti.status, COALESCE(ti.claimed_by, ''), t.status,
		       COALESCE(t.lease_owner, ''), t.lease_owner IS NOT NULL,
		       COALESCE(t.lease_until > now(), false)
		FROM task_intents AS ti
		JOIN agent_tasks AS t ON t.id = ti.task_id
		WHERE ti.id = $1`, intentID,
	).Scan(&status, &claimedBy, &taskStatus, &taskOwner, &ownerKnown, &leaseAlive)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.LeaseIntentNotFound, nil
	}
	if err != nil {
		return "", fmt.Errorf("diagnose lease: %w", err)
	}

	// Terminal tasks are checked first: an intent may still say "claimed" on a
	// task that was cancelled or finished by another path, and that case has a
	// different operator meaning than ordinary contention.
	switch taskStatus {
	case string(domain.TaskStatusSucceeded), string(domain.TaskStatusFailed),
		string(domain.TaskStatusCancelled):
		return domain.LeaseTaskFinished, nil
	}
	if status != string(domain.IntentStatusClaimed) {
		return domain.LeaseIntentNotClaimed, nil
	}
	if claimedBy != workerID {
		return domain.LeaseClaimedByOther, nil
	}
	if !ownerKnown {
		return domain.LeaseTaskOwnerChanged, nil
	}
	if taskOwner != workerID {
		return domain.LeaseTaskOwnerChanged, nil
	}
	if !leaseAlive {
		return domain.LeaseExpired, nil
	}
	return domain.LeaseOK, nil
}

func (p *Postgres) CompleteIntent(ctx context.Context, intentID, resultRef string) error {
	result := sql.NullString{String: resultRef, Valid: resultRef != ""}
	tag, err := p.db.ExecContext(ctx, `
		UPDATE task_intents SET status = 'completed', result_ref = $2
		WHERE id = $1 AND status = 'claimed'`, intentID, result)
	if err != nil {
		return fmt.Errorf("complete intent: %w", err)
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return fmt.Errorf("complete intent rows affected: %w", err)
	}
	if affected == 0 {
		return ErrUnexpectedStatus
	}
	return nil
}

func (p *Postgres) SaveCheckpoint(ctx context.Context, taskID string, checkpoint []byte) error {
	tag, err := p.db.ExecContext(ctx, `
		UPDATE agent_tasks
		SET checkpoint = $2, checkpoint_version = checkpoint_version + 1, updated_at = now()
		WHERE id = $1`, taskID, nullableJSON(checkpoint))
	if err != nil {
		return fmt.Errorf("save checkpoint: %w", err)
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return fmt.Errorf("save checkpoint rows affected: %w", err)
	}
	if affected == 0 {
		return ErrTaskNotFound
	}
	return nil
}

// FinishTaskIfDone transitions a task to a terminal status only when no
// pending or claimed intents remain, so a later planner round cannot append
// work to a task that was already closed.
func (p *Postgres) FinishTaskIfDone(ctx context.Context, taskID string, status domain.TaskStatus) (bool, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return false, fmt.Errorf("begin finish transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var remaining int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM task_intents
		WHERE task_id = $1 AND status IN ('pending', 'claimed')`, taskID,
	).Scan(&remaining); err != nil {
		return false, fmt.Errorf("count open intents: %w", err)
	}
	if remaining > 0 {
		return false, nil
	}

	tag, err := tx.ExecContext(ctx, `
		UPDATE agent_tasks
		SET status = $2, lease_owner = NULL, lease_until = NULL, updated_at = now()
		WHERE id = $1 AND status <> $2`, taskID, status)
	if err != nil {
		return false, fmt.Errorf("finish task: %w", err)
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("finish task rows affected: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return false, fmt.Errorf("commit finish transaction: %w", err)
	}
	return affected > 0, nil
}

// ListTaskEvents returns a task's events in ascending sequence order.
//
// limit caps the result, but the cap keeps the NEWEST events: a planner round
// cares about what just happened, and returning the oldest events would hide
// the attempt that failed a moment ago. The order within the window is still
// ascending so a caller can read it as a timeline.
func (p *Postgres) ListTaskEvents(ctx context.Context, taskID string, limit int) ([]domain.TaskEvent, error) {
	if limit <= 0 {
		limit = 200
	}
	rows, err := p.db.QueryContext(ctx, `
		SELECT task_id, seq, kind, schema_version, payload, at
		FROM (
			SELECT task_id, seq, kind, schema_version, payload, at
			FROM task_events
			WHERE task_id = $1
			ORDER BY seq DESC
			LIMIT $2
		) AS recent
		ORDER BY seq`, taskID, limit)
	if err != nil {
		return nil, fmt.Errorf("list task events: %w", err)
	}
	defer rows.Close()

	out := make([]domain.TaskEvent, 0, 32)
	for rows.Next() {
		var event domain.TaskEvent
		var payload []byte
		if err := rows.Scan(&event.TaskID, &event.Seq, &event.Kind,
			&event.SchemaVersion, &payload, &event.At); err != nil {
			return nil, fmt.Errorf("scan task event: %w", err)
		}
		event.Payload = payload
		out = append(out, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list task events: %w", err)
	}
	return out, nil
}

// RecoverExpiredLeases returns claimed intents to pending when the owning
// task's lease has lapsed, which is how work resumes after a worker crashes.
//
// It also clears the stale task lease. Without that, the dead worker stays
// recorded as the owner, so the audit trail names a worker that is gone and
// DiagnoseLease reports contention for a lease nobody holds.
//
// Terminal tasks are skipped: resurrecting an intent on a finished task would
// execute work that a human or another path already closed.
func (p *Postgres) RecoverExpiredLeases(ctx context.Context) (int64, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, fmt.Errorf("begin lease recovery transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// The intent update must run before the task lease is cleared: it selects
	// rows through the lapsed lease, so clearing first would match nothing.
	tag, err := tx.ExecContext(ctx, `
		UPDATE task_intents AS ti
		SET status = 'pending', claimed_by = NULL
		FROM agent_tasks AS t
		WHERE ti.task_id = t.id
		  AND ti.status = 'claimed'
		  AND t.lease_until IS NOT NULL
		  AND t.lease_until < now()
		  AND t.status IN ('queued', 'running')`)
	if err != nil {
		return 0, fmt.Errorf("recover expired leases: %w", err)
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("recover expired leases rows affected: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE agent_tasks
		SET lease_owner = NULL, lease_until = NULL, updated_at = now()
		WHERE lease_until IS NOT NULL
		  AND lease_until < now()
		  AND status IN ('queued', 'running')`); err != nil {
		return 0, fmt.Errorf("clear expired task leases: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit lease recovery transaction: %w", err)
	}
	return affected, nil
}

// FinishIdleTasks closes running tasks that have no pending or claimed intents.
// This covers a crash after the final intent completed but before the task was
// marked terminal.
func (p *Postgres) FinishIdleTasks(ctx context.Context) (int64, error) {
	tag, err := p.db.ExecContext(ctx, `
		UPDATE agent_tasks AS t
		SET status = 'succeeded', lease_owner = NULL, lease_until = NULL, updated_at = now()
		WHERE t.status = 'running'
		  AND NOT EXISTS (
		      SELECT 1 FROM task_intents AS i
		      WHERE i.task_id = t.id AND i.status IN ('pending', 'claimed')
		  )`)
	if err != nil {
		return 0, fmt.Errorf("finish idle tasks: %w", err)
	}
	return tag.RowsAffected()
}

// SetTaskStatus moves a task to an explicit status and releases its lease. It
// is used when work must stop regardless of remaining intents (waiting_review,
// failed) so a paused task cannot keep claiming new steps.
func (p *Postgres) SetTaskStatus(ctx context.Context, taskID string, status domain.TaskStatus) error {
	tag, err := p.db.ExecContext(ctx, `
		UPDATE agent_tasks
		SET status = $2, lease_owner = NULL, lease_until = NULL, updated_at = now()
		WHERE id = $1`, taskID, status)
	if err != nil {
		return fmt.Errorf("set task status: %w", err)
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return fmt.Errorf("set task status rows affected: %w", err)
	}
	if affected == 0 {
		return ErrTaskNotFound
	}
	return nil
}

func (p *Postgres) AppendTaskEvent(ctx context.Context, event domain.TaskEvent) error {
	if event.SchemaVersion == 0 {
		event.SchemaVersion = 1
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin task event transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Lock the task row so concurrent appenders for the same task serialize and
	// cannot both compute the same next seq. FOR UPDATE cannot be combined with
	// an aggregate, so the lock and the seq lookup are separate statements.
	var lockedTaskID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM agent_tasks WHERE id = $1 FOR UPDATE`, event.TaskID).
		Scan(&lockedTaskID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrTaskNotFound
		}
		return fmt.Errorf("lock task for event: %w", err)
	}

	var nextSeq int
	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(seq), 0) + 1 FROM task_events WHERE task_id = $1`,
		event.TaskID,
	).Scan(&nextSeq); err != nil {
		return fmt.Errorf("next task event seq: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO task_events (task_id, seq, kind, schema_version, payload)
		VALUES ($1, $2, $3, $4, $5)`,
		event.TaskID, nextSeq, event.Kind, event.SchemaVersion, []byte(event.Payload),
	); err != nil {
		return fmt.Errorf("append task event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit task event: %w", err)
	}
	return nil
}

func nullableJSON(value []byte) any {
	if len(value) == 0 {
		return nil
	}
	return value
}
