package domain

import (
	"context"
	"encoding/json"
	"time"
)

// VerdictRecord is a triage conclusion in queryable form. The checkpoint column
// on agent_tasks already holds the latest verdict for resume purposes; this
// table exists so a verdict survives being overwritten by the next intent and
// can be listed or filtered without parsing every task's checkpoint.
type VerdictRecord struct {
	TaskID     string          `json:"task_id"`
	IntentID   string          `json:"intent_id"`
	Verdict    string          `json:"verdict"`
	Severity   string          `json:"severity"`
	Confidence float64         `json:"confidence"`
	Payload    json.RawMessage `json:"payload"`
	CreatedAt  time.Time       `json:"created_at"`
}

// VerdictRepository persists triage conclusions independently of task
// checkpoints.
type VerdictRepository interface {
	CreateVerdict(ctx context.Context, record VerdictRecord) error
	ListVerdicts(ctx context.Context, taskID string) ([]VerdictRecord, error)
}
