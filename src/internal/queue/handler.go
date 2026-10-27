package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/hibiken/asynq"

	"soc/agent/internal/domain"
	"soc/agent/internal/store"
)

const (
	ErrTaskNotFound  = "task_not_found"
	maxIntentPerTask = 100
)

// TriageHandler drives one task forward: claim a ready intent, execute it, mark
// it complete, and append a lifecycle event. Claiming is transactional, so a
// redelivered message cannot execute the same intent twice.
type TriageHandler struct {
	tasks   domain.TaskRepository
	lease   time.Duration
	workers int
	// executor performs the actual step. When nil, intents complete without
	// doing anything, which is the pre-LLM skeleton behaviour.
	executor Executor
	// consultation is optional. When nil, a stuck intent simply exhausts its
	// budget instead of summoning a team.
	consultation Consultator
	// verdicts is optional. When nil, a verdict still lives in the task
	// checkpoint but cannot be listed or filtered independently of it.
	verdicts domain.VerdictRepository
}

// Consultator is the narrow surface the handler needs so it does not depend on
// the room package's internals.
type Consultator interface {
	SummonForTask(ctx context.Context, taskID string, signals domain.StallSignals, topic string) (string, error)
}

func NewTriageHandler(tasks domain.TaskRepository, lease time.Duration) *TriageHandler {
	return &TriageHandler{tasks: tasks, lease: lease, workers: 4}
}

// SetConsultation enables team summoning for stuck intents.
func (h *TriageHandler) SetConsultation(consultation Consultator) {
	h.consultation = consultation
}

// SetVerdicts enables persisting verdicts to their own table, independent of
// the task checkpoint.
func (h *TriageHandler) SetVerdicts(verdicts domain.VerdictRepository) {
	h.verdicts = verdicts
}

// SetExecutor enables real step execution.
func (h *TriageHandler) SetExecutor(executor Executor) {
	h.executor = executor
}

func (h *TriageHandler) Handle(ctx context.Context, task *asynq.Task) error {
	var payload struct {
		TaskID string `json:"task_id"`
	}
	if err := json.Unmarshal(task.Payload(), &payload); err != nil {
		return fmt.Errorf("decode triage payload: %w", err)
	}
	if payload.TaskID == "" {
		return errors.New("triage payload is missing task_id")
	}

	record, err := h.tasks.GetTask(ctx, payload.TaskID)
	if err != nil {
		if errors.Is(err, store.ErrTaskNotFound) {
			// The task was deleted; retrying cannot help.
			return fmt.Errorf("%s: %w", ErrTaskNotFound, err)
		}
		return fmt.Errorf("load task: %w", err)
	}

	processed := 0
	for processed < maxIntentPerTask {
		intent, err := h.tasks.ClaimIntent(ctx, payload.TaskID, workerID(ctx), h.lease)
		if errors.Is(err, store.ErrNoIntentReady) {
			return h.finish(ctx, payload.TaskID)
		}
		if err != nil {
			return fmt.Errorf("claim intent: %w", err)
		}

		// Every intent runs under a heartbeat, not just a claim. An agent intent
		// can take many minutes of model calls, which outlives the lease: without
		// renewal the intent is declared dead while it is still working, a second
		// worker claims it, and the same target is attacked twice by two workers
		// that cannot see each other.
		runCtx, stopHeartbeat, lost := h.heartbeat(ctx, intent.ID)
		result, execErr := h.execute(runCtx, record, intent)
		stopHeartbeat()

		// Losing the lease is not a failure to retry: another worker owns the
		// intent now. Writing a result here would overwrite that worker's work,
		// so this path returns without completing anything.
		if lost() {
			slog.WarnContext(ctx, "lease lost during execution; abandoning this intent",
				"task_id", payload.TaskID, "intent", intent.ID, "worker", workerID(ctx))
			return nil
		}

		if execErr != nil {
			slog.ErrorContext(ctx, "intent execution failed", "task_id", payload.TaskID, "intent", intent.ID, "error", execErr)
			// A failing intent is the one place where a team is worth the
			// token cost: the agent has objective evidence (the error) that it
			// cannot finish alone. Summoning is best-effort so a room failure
			// never masks the original error.
			h.tryConsult(ctx, payload.TaskID, intent, execErr)
			return fmt.Errorf("execute intent %s: %w", intent.ID, execErr)
		}

		if err := h.tasks.CompleteIntent(ctx, intent.ID, ""); err != nil {
			return fmt.Errorf("complete intent %s: %w", intent.ID, err)
		}
		if err := h.recordOutcome(ctx, payload.TaskID, intent, result); err != nil {
			return err
		}
		processed++

		// Waiting for a human means stop claiming: continuing would re-judge
		// the same alert and spend tokens while nobody can approve the result.
		if result.NeedsReview {
			return nil
		}
	}
	// A task with more ready intents than the per-message budget keeps running;
	// the next delivery drains the rest.
	return nil
}

// heartbeat renews the intent lease until stopped, and reports whether the
// lease was lost.
//
// The first renewal happens immediately rather than after one interval: a
// worker that crashes right after claiming is exactly the case the lease exists
// to detect, and a short interval would let a slow first step outlive an
// already-shortened lease.
func (h *TriageHandler) heartbeat(ctx context.Context, intentID string) (context.Context, func(), func() bool) {
	runCtx, cancel := context.WithCancel(ctx)
	lost := &atomic.Bool{}
	stopped := make(chan struct{})

	// A lease shorter than the interval would expire before the first renewal,
	// so the interval is capped at a third of it.
	interval := h.lease / 3
	if interval <= 0 {
		interval = time.Second
	}

	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-stopped:
				return
			case <-runCtx.Done():
				return
			case <-ticker.C:
				ok, err := h.tasks.RenewLease(runCtx, intentID, workerID(ctx), h.lease)
				if err != nil {
					// A renewal error is a database problem, not proof that the
					// lease was taken. Keep working and try again: aborting on a
					// transient error would abandon a healthy run.
					slog.WarnContext(ctx, "lease renewal failed", "intent", intentID, "error", err)
					continue
				}
				if !ok {
					lost.Store(true)
					// Cancel the work: continuing would send traffic to a target
					// that another worker now owns.
					cancel()
					return
				}
			}
		}
	}()

	stop := func() {
		// Closing an already-closed channel panics, and the heartbeats are
		// stopped from more than one path (normal exit and error paths), so the
		// guard lives here instead of at every call site.
		select {
		case <-stopped:
		default:
			close(stopped)
		}
		cancel()
	}
	return runCtx, stop, lost.Load
}

// recordOutcome appends the step result and, when required, parks the task for
// human review instead of closing it.
func (h *TriageHandler) recordOutcome(ctx context.Context, taskID string, intent domain.Intent, result ExecutionResult) error {
	payload := map[string]any{
		"intent_id": intent.ID,
		"seq":       intent.Seq,
		"kind":      intent.Kind,
		"tokens":    result.Tokens,
	}
	if result.Verdict != nil {
		payload["verdict"] = result.Verdict
	}
	if result.Summary != "" {
		payload["summary"] = result.Summary
	}
	if err := h.tasks.AppendTaskEvent(ctx, domain.TaskEvent{
		TaskID:  taskID,
		Kind:    "intent_completed",
		Payload: mustJSON(payload),
	}); err != nil {
		return fmt.Errorf("append task event: %w", err)
	}

	if result.Verdict != nil {
		if err := h.tasks.SaveCheckpoint(ctx, taskID, mustJSON(result.Verdict)); err != nil {
			return fmt.Errorf("save verdict checkpoint: %w", err)
		}
		// Best-effort: the checkpoint above is already the durable record a
		// resumed task reads, so a failure here must not fail the intent, only
		// weaken the ability to list past verdicts.
		if h.verdicts != nil {
			if err := h.verdicts.CreateVerdict(ctx, domain.VerdictRecord{
				TaskID:     taskID,
				IntentID:   intent.ID,
				Verdict:    result.Verdict.Verdict,
				Severity:   result.Verdict.Severity,
				Confidence: result.Verdict.Confidence,
				Payload:    mustJSON(result.Verdict),
			}); err != nil {
				slog.WarnContext(ctx, "verdict not recorded in verdicts table", "task_id", taskID, "intent", intent.ID, "error", err)
			}
		}
	}

	if !result.NeedsReview {
		return nil
	}

	// Park the task. The event records why, so a reviewer sees the reason
	// without reading model output.
	if err := h.tasks.SetTaskStatus(ctx, taskID, domain.TaskStatusWaitingReview); err != nil {
		return fmt.Errorf("mark task for review: %w", err)
	}
	return h.tasks.AppendTaskEvent(ctx, domain.TaskEvent{
		TaskID: taskID,
		Kind:   "task_waiting_review",
		Payload: mustJSON(map[string]any{
			"intent_id": intent.ID,
			"reasons":   result.ReviewWhy,
			"verdict":   result.Verdict,
		}),
	})
}

// tryConsult summons a team when an intent fails. The decision is recorded as a
// task event either way, so a refused summon (e.g. no team configured, or a
// duplicate escalation) is visible in the audit trail rather than silent.
func (h *TriageHandler) tryConsult(ctx context.Context, taskID string, intent domain.Intent, execErr error) {
	if h.consultation == nil {
		return
	}

	// A failed execution is objective evidence of a stall: the agent tried and
	// errored, which is exactly the corroboration the policy requires.
	signals := domain.StallSignals{ToolErrors: 3}
	topic := fmt.Sprintf("intent %s (%s) failed and needs escalation", intent.ID, intent.Kind)

	summary, err := h.consultation.SummonForTask(ctx, taskID, signals, topic)
	if err != nil {
		slog.WarnContext(ctx, "consultation not opened", "task_id", taskID, "intent", intent.ID, "error", err)
		_ = h.tasks.AppendTaskEvent(ctx, domain.TaskEvent{
			TaskID: taskID,
			Kind:   "consultation_rejected",
			Payload: mustJSON(map[string]any{
				"intent_id": intent.ID,
				"reason":    err.Error(),
			}),
		})
		return
	}

	slog.InfoContext(ctx, "consultation completed", "task_id", taskID, "intent", intent.ID, "summary", summary)
	_ = h.tasks.AppendTaskEvent(ctx, domain.TaskEvent{
		TaskID: taskID,
		Kind:   "consultation_completed",
		Payload: mustJSON(map[string]any{
			"intent_id":  intent.ID,
			"summary":    summary,
			"exec_error": execErr.Error(),
		}),
	})
}

// finish closes a task once nothing is left to do and records the transition.
func (h *TriageHandler) finish(ctx context.Context, taskID string) error {
	finished, err := h.tasks.FinishTaskIfDone(ctx, taskID, domain.TaskStatusSucceeded)
	if err != nil {
		return fmt.Errorf("finish task: %w", err)
	}
	if !finished {
		return nil
	}
	return h.tasks.AppendTaskEvent(ctx, domain.TaskEvent{
		TaskID:  taskID,
		Kind:    "task_succeeded",
		Payload: mustJSON(map[string]any{"status": domain.TaskStatusSucceeded}),
	})
}

// execute runs one intent. A nil executor is the skeleton mode: the step is
// recorded as done without doing work, which keeps local development running
// before any model is configured.
func (h *TriageHandler) execute(ctx context.Context, task domain.Task, intent domain.Intent) (ExecutionResult, error) {
	if h.executor == nil {
		return ExecutionResult{Kind: intent.Kind}, nil
	}
	return h.executor.Execute(ctx, task, intent)
}

func workerID(ctx context.Context) string {
	if value, ok := ctx.Value(workerIDKey{}).(string); ok && value != "" {
		return value
	}
	return "worker"
}

type workerIDKey struct{}

func WithWorkerID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, workerIDKey{}, id)
}

func mustJSON(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return encoded
}
