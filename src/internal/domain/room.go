package domain

import (
	"encoding/json"
	"time"
)

type RoomStatus string

const (
	RoomStatusOpen      RoomStatus = "open"
	RoomStatusSummoning RoomStatus = "summoning"
	RoomStatusDeciding  RoomStatus = "deciding"
	RoomStatusClosed    RoomStatus = "closed"
	RoomStatusEscalated RoomStatus = "escalated"
)

// SummonTrigger records who caused a room to open. The trigger decides which
// evidence a summon needs: a human needs none, an agent needs corroboration.
type SummonTrigger string

const (
	SummonTriggerUser  SummonTrigger = "user"
	SummonTriggerStall SummonTrigger = "stall"
	SummonTriggerAgent SummonTrigger = "agent_request"
)

// RoomBudget bounds the cost of one consultation. Turns are hard-capped so a
// room costs O(participants), never O(participants x rounds).
type RoomBudget struct {
	MaxParticipants  int `json:"max_participants"`
	MaxRounds        int `json:"max_rounds"`
	MaxTokensPerTurn int `json:"max_tokens_per_turn"`
	MaxTotalTokens   int `json:"max_total_tokens"`
}

// DefaultRoomBudget is deliberately small: a consultation is a short
// interruption, not a second work session.
func DefaultRoomBudget() RoomBudget {
	return RoomBudget{
		MaxParticipants:  6,
		MaxRounds:        1,
		MaxTokensPerTurn: 1024,
		MaxTotalTokens:   12000,
	}
}

type Room struct {
	ID          string          `json:"id"`
	WorkspaceID string          `json:"workspace_id"`
	TeamID      string          `json:"team_id,omitempty"`
	TaskID      string          `json:"task_id,omitempty"`
	Topic       string          `json:"topic"`
	Trigger     SummonTrigger   `json:"trigger"`
	Status      RoomStatus      `json:"status"`
	Budget      RoomBudget      `json:"budget"`
	Decision    json.RawMessage `json:"decision,omitempty"`
	OpenedBy    string          `json:"opened_by"`
	CreatedAt   time.Time       `json:"created_at"`
	ClosedAt    *time.Time      `json:"closed_at,omitempty"`
}

// RoomParticipant is one invited agent. State tracks whether it actually spoke
// so a partial consultation is visible rather than silently truncated.
type RoomParticipant struct {
	RoomID     string `json:"room_id"`
	AgentKey   string `json:"agent_key"`
	Duty       string `json:"duty"`
	ModelRole  string `json:"model_role"`
	State      string `json:"state"`
	TokensUsed int    `json:"tokens_used"`
	// TurnBudget overrides the room's per-turn cap when a member is expected
	// to produce a longer synthesis.
	TurnBudget int `json:"turn_budget"`
	Position   int `json:"position"`
}

const (
	ParticipantInvited = "invited"
	ParticipantSpoke   = "spoke"
	ParticipantSkipped = "skipped"
)

// RoomEvent kinds. The sequence is the audit trail of a consultation.
const (
	RoomEventOpened        = "room_opened"
	RoomEventBriefPosted   = "brief_posted"
	RoomEventAgentTurn     = "agent_turn"
	RoomEventAgentSkipped  = "agent_skipped"
	RoomEventSynthesis     = "synthesis"
	RoomEventDecision      = "decision"
	RoomEventClosed        = "closed"
	RoomEventEscalated     = "escalated_to_human"
	RoomEventBudgetStopped = "budget_stopped"
)

type RoomEvent struct {
	RoomID        string          `json:"room_id"`
	Seq           int             `json:"seq"`
	Kind          string          `json:"kind"`
	Actor         string          `json:"actor"`
	SchemaVersion int             `json:"schema_version"`
	Payload       json.RawMessage `json:"payload"`
	At            time.Time       `json:"at"`
}

// EvidenceRef points at something the team can verify, never at prose. A room
// that cannot cite evidence cannot make a decision.
type EvidenceRef struct {
	Kind  string `json:"kind"` // alert_field / kb_chunk / intel_ioc / tool_output
	Ref   string `json:"ref"`
	Quote string `json:"quote,omitempty"`
}

// RoomBrief is the escalating agent's structured problem statement. Sending a
// brief instead of a full transcript is what keeps the consultation cheap.
type RoomBrief struct {
	Problem  string          `json:"problem"`
	Attempts []string        `json:"attempts"`
	Evidence []EvidenceRef   `json:"evidence"`
	Missing  []string        `json:"missing"`
	Ask      string          `json:"ask"`
	Context  json.RawMessage `json:"context,omitempty"`
}

// RoomDecision is the consultation's output. NextOwner names the agent that
// resumes work so a decision cannot stall silently.
type RoomDecision struct {
	Outcome   string        `json:"outcome"` // proceed / rework / escalate_human / abandon
	Rationale string        `json:"rationale"`
	Actions   []string      `json:"actions"`
	NextOwner string        `json:"next_owner,omitempty"`
	Evidence  []EvidenceRef `json:"evidence,omitempty"`
}

// Escalation links a stuck task to the room that resolved it.
type Escalation struct {
	ID         string          `json:"id"`
	TaskID     string          `json:"task_id"`
	RoomID     string          `json:"room_id,omitempty"`
	Trigger    SummonTrigger   `json:"trigger"`
	Reasons    []string        `json:"reasons"`
	Signals    json.RawMessage `json:"signals"`
	Status     string          `json:"status"`
	CreatedAt  time.Time       `json:"created_at"`
	ResolvedAt *time.Time      `json:"resolved_at,omitempty"`
}

// StallSignals are objective, code-computed facts about a struggling agent.
// Only these can justify a summon; a model's opinion is never sufficient
// alone, otherwise "I need help" becomes a way to avoid work.
type StallSignals struct {
	StepsUsed         int           `json:"steps_used"`
	StepBudget        int           `json:"step_budget"`
	RepeatedToolCalls int           `json:"repeated_tool_calls"`
	Confidence        float64       `json:"confidence"`
	ConfidenceFloor   float64       `json:"confidence_floor"`
	MissingEvidence   int           `json:"missing_evidence"`
	Contradictions    int           `json:"contradictions"`
	Elapsed           time.Duration `json:"elapsed_ns"`
	Deadline          time.Duration `json:"deadline_ns"`
	ToolErrors        int           `json:"tool_errors"`
}

// Reason identifiers returned by Evaluate. They are stable strings so they can
// be stored, grepped, and asserted in tests.
const (
	ReasonStepBudget       = "step_budget_exhausted"
	ReasonRepeatedToolCall = "repeated_tool_calls"
	ReasonLowConfidence    = "low_confidence"
	ReasonMissingEvidence  = "missing_evidence"
	ReasonContradiction    = "contradictory_evidence"
	ReasonDeadlineNear     = "deadline_near"
	ReasonToolErrors       = "tool_errors"
)

// Evaluate returns every objective reason the agent looks stuck. Empty means
// "still making progress", which is what blocks a model-requested summon.
func (s StallSignals) Evaluate() []string {
	reasons := make([]string, 0, 6)
	if s.StepBudget > 0 && s.StepsUsed >= s.StepBudget {
		reasons = append(reasons, ReasonStepBudget)
	}
	if s.RepeatedToolCalls >= 3 {
		reasons = append(reasons, ReasonRepeatedToolCall)
	}
	// A zero confidence is "not assessed yet", not "very unsure".
	if s.Confidence > 0 && s.ConfidenceFloor > 0 && s.Confidence < s.ConfidenceFloor {
		reasons = append(reasons, ReasonLowConfidence)
	}
	if s.MissingEvidence >= 2 {
		reasons = append(reasons, ReasonMissingEvidence)
	}
	if s.Contradictions >= 2 {
		reasons = append(reasons, ReasonContradiction)
	}
	if s.Deadline > 0 && s.Elapsed > 0 && s.Elapsed >= s.Deadline*4/5 {
		reasons = append(reasons, ReasonDeadlineNear)
	}
	if s.ToolErrors >= 3 {
		reasons = append(reasons, ReasonToolErrors)
	}
	return reasons
}
