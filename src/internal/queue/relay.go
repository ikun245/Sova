package queue

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/hibiken/asynq"

	"soc/agent/internal/domain"
)

const (
	// TopicTaskQueued announces that a task's first intent is ready. Consumers
	// claim intents from PostgreSQL; the message is only a wake-up hint.
	TopicTaskQueued = "task.queued"
	TaskTypeTriage  = "task:triage"
)

// Enqueuer is the small surface the relay needs, which keeps it testable
// without a live Redis.
type Enqueuer interface {
	EnqueueTask(ctx context.Context, taskID string, opts ...asynq.Option) error
}

type AsynqEnqueuer struct {
	client *asynq.Client
}

func NewAsynqEnqueuer(redisAddr string) *AsynqEnqueuer {
	return &AsynqEnqueuer{client: asynq.NewClient(asynq.RedisClientOpt{Addr: redisAddr})}
}

func (e *AsynqEnqueuer) EnqueueTask(_ context.Context, taskID string, opts ...asynq.Option) error {
	payload, err := json.Marshal(map[string]string{"task_id": taskID})
	if err != nil {
		return fmt.Errorf("encode triage task: %w", err)
	}
	if _, err := e.client.Enqueue(asynq.NewTask(TaskTypeTriage, payload), opts...); err != nil {
		return fmt.Errorf("enqueue triage task: %w", err)
	}
	return nil
}

func (e *AsynqEnqueuer) Close() error {
	return e.client.Close()
}

// Relay publishes committed outbox rows. It is safe to run in more than one
// process: PublishPending uses FOR UPDATE SKIP LOCKED, and re-publishing a
// message is harmless because consumers claim intents idempotently.
type Relay struct {
	outbox   domain.OutboxRepository
	enqueuer Enqueuer
	batch    int
}

func NewRelay(outbox domain.OutboxRepository, enqueuer Enqueuer) *Relay {
	return &Relay{outbox: outbox, enqueuer: enqueuer, batch: 50}
}

func (r *Relay) Run(ctx context.Context, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if err := r.Drain(ctx); err != nil {
			slog.ErrorContext(ctx, "outbox relay drain failed", "error", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func (r *Relay) Drain(ctx context.Context) error {
	items, err := r.outbox.PublishPending(ctx, r.batch)
	if err != nil {
		return err
	}
	if len(items) == 0 {
		return nil
	}

	published := make([]int64, 0, len(items))
	for _, item := range items {
		if err := r.publish(ctx, item); err != nil {
			slog.ErrorContext(ctx, "publish outbox message failed",
				"id", item.ID, "topic", item.Topic, "error", err)
			if failErr := r.outbox.MarkFailed(ctx, item.ID, err.Error()); failErr != nil {
				slog.ErrorContext(ctx, "mark outbox failed", "id", item.ID, "error", failErr)
			}
			continue
		}
		published = append(published, item.ID)
	}
	return r.outbox.MarkPublished(ctx, published)
}

func (r *Relay) publish(ctx context.Context, item domain.OutboxItem) error {
	switch item.Topic {
	case TopicTaskQueued:
		var payload struct {
			TaskID string `json:"task_id"`
		}
		if err := json.Unmarshal(item.Payload, &payload); err != nil {
			return fmt.Errorf("decode %s payload: %w", item.Topic, err)
		}
		if payload.TaskID == "" {
			return fmt.Errorf("decode %s payload: missing task_id", item.Topic)
		}
		return r.enqueuer.EnqueueTask(ctx, payload.TaskID)
	default:
		return fmt.Errorf("unknown outbox topic %q", item.Topic)
	}
}
