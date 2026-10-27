package domain

import (
	"context"
	"encoding/json"
)

// OutboxMessage is written in the same transaction as the state change it
// announces. A relay publishes it afterwards, so a crash between commit and
// enqueue cannot lose the work.
type OutboxMessage struct {
	Topic   string          `json:"topic"`
	Payload json.RawMessage `json:"payload"`
}

// AlertIngest writes the alert, its task, its intents, and the outbox message
// atomically. created is false when the dedup key already existed, in which
// case no task or outbox row is added.
type AlertIngest interface {
	IngestAlert(ctx context.Context, alert Alert, task Task, intents []Intent, message OutboxMessage) (Alert, bool, error)
}

type OutboxRepository interface {
	// PublishPending claims up to limit unpublished messages and reports them.
	PublishPending(ctx context.Context, limit int) ([]OutboxItem, error)
	MarkPublished(ctx context.Context, ids []int64) error
	MarkFailed(ctx context.Context, id int64, reason string) error
}

type OutboxItem struct {
	ID       int64           `json:"id"`
	Topic    string          `json:"topic"`
	Payload  json.RawMessage `json:"payload"`
	Attempts int             `json:"attempts"`
}
