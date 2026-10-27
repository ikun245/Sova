package domain

import (
	"encoding/json"
	"time"
)

type TaskStatus string

const (
	TaskStatusQueued          TaskStatus = "queued"
	TaskStatusRunning         TaskStatus = "running"
	TaskStatusWaitingReview   TaskStatus = "waiting_review"
	TaskStatusWaitingApproval TaskStatus = "waiting_approval"
	TaskStatusSucceeded       TaskStatus = "succeeded"
	TaskStatusFailed          TaskStatus = "failed"
	TaskStatusCancelled       TaskStatus = "cancelled"
)

type IntentStatus string

const (
	IntentStatusPending   IntentStatus = "pending"
	IntentStatusClaimed   IntentStatus = "claimed"
	IntentStatusCompleted IntentStatus = "completed"
	IntentStatusBlocked   IntentStatus = "blocked"
	IntentStatusCancelled IntentStatus = "cancelled"
)

// Task is the durable truth for one unit of agent work. Its checkpoint is the
// graph state needed to resume after a worker restart.
type Task struct {
	ID                string          `json:"id"`
	TenantID          string          `json:"tenant_id"`
	CaseID            string          `json:"case_id,omitempty"`
	Status            TaskStatus      `json:"status"`
	Checkpoint        json.RawMessage `json:"checkpoint,omitempty"`
	CheckpointVersion int             `json:"checkpoint_version"`
	LeaseOwner        string          `json:"-"`
	LeaseUntil        *time.Time      `json:"-"`
	Attempt           int             `json:"attempt"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

// Intent is one step from the planner's persistent todolist. A worker may only
// claim an intent whose dependencies are all completed.
type Intent struct {
	ID        string          `json:"id"`
	TaskID    string          `json:"task_id"`
	Seq       int             `json:"seq"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload"`
	DependsOn []string        `json:"depends_on"`
	Status    IntentStatus    `json:"status"`
	ClaimedBy string          `json:"-"`
	ResultRef string          `json:"result_ref,omitempty"`
}

// TaskEvent is an append-only lifecycle record. Seq is monotonic per task so a
// replaying consumer can detect gaps instead of silently skipping history.
type TaskEvent struct {
	TaskID        string          `json:"task_id"`
	Seq           int             `json:"seq"`
	Kind          string          `json:"kind"`
	SchemaVersion int             `json:"schema_version"`
	Payload       json.RawMessage `json:"payload"`
	At            time.Time       `json:"at"`
}
