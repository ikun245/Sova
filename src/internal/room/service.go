package room

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"soc/agent/internal/domain"
)

// TurnRole distinguishes a participant's single speaking turn from the
// synthesizer's decision turn, which additionally sees every reply.
type TurnRole string

const (
	TurnParticipant TurnRole = "participant"
	TurnSynthesizer TurnRole = "synthesizer"
)

// TurnRequest is everything one agent sees in a consultation. A participant
// gets the brief and its own role; it never gets the other agents' full
// histories, which is what keeps the cost linear.
type TurnRequest struct {
	RoomID    string
	AgentKey  string
	Duty      string
	ModelRole string
	Topic     string
	Role      TurnRole
	Brief     domain.RoomBrief
	Replies   []TurnResult
	MaxTokens int
}

type TurnResult struct {
	AgentKey string
	Text     string
	Tokens   int
}

// Contributor asks one agent one bounded turn. Implementations resolve the
// agent's model through its role binding; the room never touches credentials.
type Contributor interface {
	Ask(ctx context.Context, req TurnRequest) (TurnResult, error)
}

// SummonRequest is the input to a consultation.
type SummonRequest struct {
	WorkspaceID string
	TeamID      string
	TaskID      string
	Topic       string
	Trigger     domain.SummonTrigger
	OpenedBy    string
	// AgentRequested records that the calling agent explicitly asked for
	// help. It is only meaningful with SummonTriggerAgent.
	AgentRequested bool
	Signals        domain.StallSignals
	Brief          domain.RoomBrief
	Budget         domain.RoomBudget
	// Synthesizer overrides which member writes the decision. Empty means
	// "the member with duty critic, else the first member".
	Synthesizer string
}

// Outcome reports what the consultation produced, including whether the
// budget cut it short so callers do not mistake a truncated room for a
// thorough one.
type Outcome struct {
	RoomID       string
	Decision     domain.RoomDecision
	Participants []domain.RoomParticipant
	TokensUsed   int
	// Stopped is non-empty when the room ended early, e.g. "budget" or
	// "no_participants".
	Stopped string
}

type Service struct {
	rooms       domain.RoomRepository
	teams       domain.TeamRepository
	contributor Contributor
	policy      Policy
	now         func() time.Time
	newID       func() (string, error)
}

func NewService(rooms domain.RoomRepository, teams domain.TeamRepository, contributor Contributor, policy Policy) *Service {
	return &Service{
		rooms:       rooms,
		teams:       teams,
		contributor: contributor,
		policy:      policy,
		now:         time.Now,
		newID:       randomID,
	}
}

// Summon opens a room, runs one bounded round of consultation, and returns the
// decision. Cost is (participants + 1) model calls at most, regardless of how
// long the underlying task takes.
func (s *Service) Summon(ctx context.Context, req SummonRequest) (Outcome, error) {
	auth, err := s.policy.Authorize(req.Trigger, req.AgentRequested, req.Signals)
	if err != nil {
		return Outcome{}, err
	}

	budget := req.Budget
	if budget.MaxParticipants <= 0 {
		budget = domain.DefaultRoomBudget()
	}

	members, err := s.membersFor(ctx, req.TeamID, budget.MaxParticipants)
	if err != nil {
		return Outcome{}, err
	}
	if len(members) == 0 {
		return Outcome{}, errors.New("room: no enabled team members to consult")
	}

	roomID, err := s.newID()
	if err != nil {
		return Outcome{}, fmt.Errorf("room: generate room id: %w", err)
	}

	participants := make([]domain.RoomParticipant, 0, len(members))
	for _, member := range members {
		participants = append(participants, domain.RoomParticipant{
			RoomID:     roomID,
			AgentKey:   member.AgentKey,
			Duty:       member.Duty,
			ModelRole:  member.ModelRole,
			State:      domain.ParticipantInvited,
			TurnBudget: member.TurnBudget,
			Position:   member.Position,
		})
	}

	room := domain.Room{
		ID:          roomID,
		WorkspaceID: req.WorkspaceID,
		TeamID:      req.TeamID,
		TaskID:      req.TaskID,
		Topic:       sanitizeTopic(req.Topic),
		Trigger:     req.Trigger,
		Status:      domain.RoomStatusSummoning,
		Budget:      budget,
		OpenedBy:    req.OpenedBy,
	}
	if _, err := s.rooms.CreateRoom(ctx, room, participants); err != nil {
		return Outcome{}, fmt.Errorf("room: create: %w", err)
	}

	// De-duplicate: a retrying agent must not open a second room for the same
	// wall. The repository enforces one open escalation per task.
	var escalation domain.Escalation
	if req.TaskID != "" {
		escalationID, err := s.newID()
		if err != nil {
			return Outcome{}, fmt.Errorf("room: generate escalation id: %w", err)
		}
		created, isNew, err := s.rooms.OpenEscalation(ctx, domain.Escalation{
			ID:      escalationID,
			TaskID:  req.TaskID,
			RoomID:  roomID,
			Trigger: req.Trigger,
			Reasons: auth.Reasons,
			Signals: mustJSON(req.Signals),
			Status:  "in_room",
		})
		if err != nil {
			return Outcome{}, fmt.Errorf("room: open escalation: %w", err)
		}
		if !isNew {
			return Outcome{}, fmt.Errorf("room: task %s already has an open escalation (%s)", req.TaskID, created.RoomID)
		}
		escalation = created
	}

	s.appendEvent(ctx, roomID, domain.RoomEventOpened, req.OpenedBy, map[string]any{
		"trigger": req.Trigger,
		"reasons": auth.Reasons,
		"budget":  budget,
	})
	s.appendEvent(ctx, roomID, domain.RoomEventBriefPosted, req.OpenedBy, req.Brief)

	outcome := Outcome{RoomID: roomID, Participants: participants}
	replies := make([]TurnResult, 0, len(participants))

	for i := range participants {
		participant := participants[i]
		if budget.MaxTotalTokens > 0 && outcome.TokensUsed >= budget.MaxTotalTokens {
			outcome.Stopped = "budget"
			s.appendEvent(ctx, roomID, domain.RoomEventBudgetStopped, "system", map[string]any{
				"tokens_used": outcome.TokensUsed,
				"reason":      "total token budget exhausted before all participants spoke",
			})
			break
		}

		maxTokens := budget.MaxTokensPerTurn
		if participant.TurnBudget > 0 && participant.TurnBudget < maxTokens {
			maxTokens = participant.TurnBudget
		}

		result, askErr := s.contributor.Ask(ctx, TurnRequest{
			RoomID:    roomID,
			AgentKey:  participant.AgentKey,
			Duty:      participant.Duty,
			ModelRole: participant.ModelRole,
			Topic:     room.Topic,
			Role:      TurnParticipant,
			Brief:     req.Brief,
			MaxTokens: maxTokens,
		})
		if askErr != nil {
			// One failing agent must not sink the consultation.
			participants[i].State = domain.ParticipantSkipped
			_ = s.rooms.UpdateParticipant(ctx, roomID, participant.AgentKey, domain.ParticipantSkipped, 0)
			s.appendEvent(ctx, roomID, domain.RoomEventAgentSkipped, participant.AgentKey, map[string]any{
				"error": askErr.Error(),
			})
			continue
		}

		participants[i].State = domain.ParticipantSpoke
		participants[i].TokensUsed = result.Tokens
		outcome.TokensUsed += result.Tokens
		_ = s.rooms.UpdateParticipant(ctx, roomID, participant.AgentKey, domain.ParticipantSpoke, result.Tokens)

		replies = append(replies, result)
		s.appendEvent(ctx, roomID, domain.RoomEventAgentTurn, participant.AgentKey, map[string]any{
			"duty":   participant.Duty,
			"text":   result.Text,
			"tokens": result.Tokens,
		})
	}

	decision := s.synthesize(ctx, req, room, replies, participants, budget, &outcome)
	outcome.Decision = decision
	outcome.Participants = participants

	status := domain.RoomStatusClosed
	if decision.Outcome == "escalate_human" {
		status = domain.RoomStatusEscalated
	}
	decisionJSON := mustJSON(decision)
	s.appendEvent(ctx, roomID, domain.RoomEventDecision, "system", decision)
	if err := s.rooms.CloseRoom(ctx, roomID, status, decisionJSON); err != nil {
		return outcome, fmt.Errorf("room: close: %w", err)
	}
	s.appendEvent(ctx, roomID, domain.RoomEventClosed, "system", map[string]any{
		"status":      status,
		"tokens_used": outcome.TokensUsed,
		"stopped":     outcome.Stopped,
	})

	if escalation.ID != "" {
		_ = s.rooms.ResolveEscalation(ctx, escalation.ID, roomID, "resolved")
	}
	return outcome, nil
}

// synthesize asks one agent to turn the replies into a decision. A malformed
// answer degrades to human escalation rather than being silently accepted.
func (s *Service) synthesize(
	ctx context.Context,
	req SummonRequest,
	room domain.Room,
	replies []TurnResult,
	participants []domain.RoomParticipant,
	budget domain.RoomBudget,
	outcome *Outcome,
) domain.RoomDecision {
	if len(replies) == 0 {
		outcome.Stopped = "no_replies"
		return domain.RoomDecision{
			Outcome:   "escalate_human",
			Rationale: "no participant produced a usable reply",
			NextOwner: req.OpenedBy,
		}
	}

	synthesizer := req.Synthesizer
	if synthesizer == "" {
		synthesizer = pickSynthesizer(participants, replies)
	}
	maxTokens := budget.MaxTokensPerTurn
	if maxTokens < 1500 {
		maxTokens = 1500 // a decision needs more room than one opinion
	}
	if budget.MaxTotalTokens > 0 && outcome.TokensUsed+maxTokens > budget.MaxTotalTokens {
		outcome.Stopped = "budget"
		return domain.RoomDecision{
			Outcome:   "escalate_human",
			Rationale: "token budget exhausted before synthesis; replies are recorded for a human",
			NextOwner: req.OpenedBy,
		}
	}

	result, err := s.contributor.Ask(ctx, TurnRequest{
		RoomID:    room.ID,
		AgentKey:  synthesizer,
		ModelRole: "",
		Topic:     room.Topic,
		Role:      TurnSynthesizer,
		Brief:     req.Brief,
		Replies:   replies,
		MaxTokens: maxTokens,
	})
	if err != nil {
		outcome.Stopped = "synthesis_failed"
		return domain.RoomDecision{
			Outcome:   "escalate_human",
			Rationale: "synthesis failed: " + err.Error(),
			NextOwner: req.OpenedBy,
		}
	}
	outcome.TokensUsed += result.Tokens
	s.appendEvent(ctx, room.ID, domain.RoomEventSynthesis, synthesizer, map[string]any{
		"text":   result.Text,
		"tokens": result.Tokens,
	})

	var decision domain.RoomDecision
	if err := json.Unmarshal([]byte(extractJSON(result.Text)), &decision); err != nil || decision.Outcome == "" {
		return domain.RoomDecision{
			Outcome:   "escalate_human",
			Rationale: "synthesizer did not return a structured decision; raw reply attached for review",
			Actions:   []string{result.Text},
			NextOwner: req.OpenedBy,
		}
	}
	if decision.NextOwner == "" {
		decision.NextOwner = req.OpenedBy
	}
	return decision
}

// pickSynthesizer prefers the critic because a decision should be challenged
// before it is adopted. Order is deterministic so a room replays identically.
func pickSynthesizer(participants []domain.RoomParticipant, replies []TurnResult) string {
	spoke := make(map[string]bool, len(replies))
	for _, reply := range replies {
		spoke[reply.AgentKey] = true
	}
	for _, participant := range participants {
		if participant.Duty == "critic" && spoke[participant.AgentKey] {
			return participant.AgentKey
		}
	}
	return replies[0].AgentKey
}

func (s *Service) membersFor(ctx context.Context, teamID string, limit int) ([]domain.TeamMember, error) {
	if s.teams == nil || teamID == "" {
		return nil, errors.New("room: a team is required to summon a consultation")
	}
	members, err := s.teams.ListTeamMembers(ctx, teamID)
	if err != nil {
		return nil, fmt.Errorf("room: load team members: %w", err)
	}
	enabled := make([]domain.TeamMember, 0, len(members))
	for _, member := range members {
		if member.Enabled {
			enabled = append(enabled, member)
		}
	}
	if limit > 0 && len(enabled) > limit {
		enabled = enabled[:limit]
	}
	return enabled, nil
}

func (s *Service) appendEvent(ctx context.Context, roomID, kind, actor string, payload any) {
	_, _ = s.rooms.AppendRoomEvent(ctx, domain.RoomEvent{
		RoomID:        roomID,
		Kind:          kind,
		Actor:         actor,
		SchemaVersion: 1,
		Payload:       mustJSON(payload),
	})
}

// extractJSON tolerates a model wrapping its JSON in prose or fences.
func extractJSON(text string) string {
	start := -1
	for i := 0; i < len(text); i++ {
		if text[i] == '{' {
			start = i
			break
		}
	}
	if start < 0 {
		return text
	}
	end := -1
	for i := len(text) - 1; i >= start; i-- {
		if text[i] == '}' {
			end = i
			break
		}
	}
	if end < 0 {
		return text
	}
	return text[start : end+1]
}

func mustJSON(value any) json.RawMessage {
	encoded, err := json.Marshal(value)
	if err != nil {
		return json.RawMessage(`{}`)
	}
	return encoded
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
