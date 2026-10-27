package room

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"soc/agent/internal/domain"
)

type fakeRoomRepo struct {
	room           domain.Room
	participants   []domain.RoomParticipant
	events         []domain.RoomEvent
	seq            int
	closedStatus   domain.RoomStatus
	decision       json.RawMessage
	escalations    map[string]domain.Escalation
	escalationOpen bool
	participantLog []string
}

func newFakeRoomRepo() *fakeRoomRepo {
	return &fakeRoomRepo{escalations: map[string]domain.Escalation{}}
}

func (f *fakeRoomRepo) CreateRoom(_ context.Context, room domain.Room, participants []domain.RoomParticipant) (domain.Room, error) {
	f.room = room
	f.participants = participants
	return room, nil
}

func (f *fakeRoomRepo) GetRoom(context.Context, string) (domain.Room, error) {
	return f.room, nil
}

func (f *fakeRoomRepo) AppendRoomEvent(_ context.Context, event domain.RoomEvent) (domain.RoomEvent, error) {
	f.seq++
	event.Seq = f.seq
	f.events = append(f.events, event)
	return event, nil
}

func (f *fakeRoomRepo) ListRoomEvents(context.Context, string) ([]domain.RoomEvent, error) {
	return f.events, nil
}

func (f *fakeRoomRepo) UpdateParticipant(_ context.Context, _, agentKey, state string, _ int) error {
	f.participantLog = append(f.participantLog, agentKey+":"+state)
	return nil
}

func (f *fakeRoomRepo) CloseRoom(_ context.Context, _ string, status domain.RoomStatus, decision json.RawMessage) error {
	f.closedStatus = status
	f.decision = decision
	return nil
}

func (f *fakeRoomRepo) OpenEscalation(_ context.Context, escalation domain.Escalation) (domain.Escalation, bool, error) {
	if f.escalationOpen {
		existing := f.escalations[escalation.TaskID]
		return existing, false, nil
	}
	f.escalationOpen = true
	f.escalations[escalation.TaskID] = escalation
	return escalation, true, nil
}

func (f *fakeRoomRepo) ResolveEscalation(context.Context, string, string, string) error {
	f.escalationOpen = false
	return nil
}

type fakeTeamRepo struct {
	members []domain.TeamMember
	err     error
}

func (f *fakeTeamRepo) CreateTeam(_ context.Context, team domain.Team, _ []domain.TeamMember) (domain.Team, error) {
	return team, nil
}

func (f *fakeTeamRepo) ListTeams(context.Context, string) ([]domain.Team, error) {
	return nil, nil
}

func (f *fakeTeamRepo) ListTeamMembers(context.Context, string) ([]domain.TeamMember, error) {
	return f.members, f.err
}

// fakeContributor answers deterministically and records every call so tests can
// assert the consultation ran a bounded number of turns.
type fakeContributor struct {
	calls     []TurnRequest
	tokens    int
	failAgent string
	decision  string
}

func (f *fakeContributor) Ask(_ context.Context, req TurnRequest) (TurnResult, error) {
	f.calls = append(f.calls, req)
	if f.failAgent != "" && req.AgentKey == f.failAgent {
		return TurnResult{}, errors.New("agent unavailable")
	}
	if req.Role == TurnSynthesizer {
		text := f.decision
		if text == "" {
			text = `{"outcome":"proceed","rationale":"team agreed on next step","actions":["retry with CVE context"],"next_owner":"triage"}`
		}
		return TurnResult{AgentKey: req.AgentKey, Text: text, Tokens: f.tokens}, nil
	}
	return TurnResult{AgentKey: req.AgentKey, Text: "my view from " + req.Duty, Tokens: f.tokens}, nil
}

func threeMembers() []domain.TeamMember {
	return []domain.TeamMember{
		{AgentKey: "triage", Duty: "triage", ModelRole: "triage", Enabled: true, Position: 0},
		{AgentKey: "intel", Duty: "intel", ModelRole: "summary", Enabled: true, Position: 1},
		{AgentKey: "critic", Duty: "critic", ModelRole: "triage", Enabled: true, Position: 2},
	}
}

func stalledSignals() domain.StallSignals {
	return domain.StallSignals{StepsUsed: 12, StepBudget: 12}
}

func newTestService(repo *fakeRoomRepo, teams *fakeTeamRepo, contributor *fakeContributor) *Service {
	service := NewService(repo, teams, contributor, DefaultPolicy())
	service.newID = func() (string, error) { return "id-1", nil }
	return service
}

func TestSummonRunsOneBoundedRound(t *testing.T) {
	repo := newFakeRoomRepo()
	contributor := &fakeContributor{tokens: 100}
	service := newTestService(repo, &fakeTeamRepo{members: threeMembers()}, contributor)

	outcome, err := service.Summon(context.Background(), SummonRequest{
		WorkspaceID: "ws-1",
		TeamID:      "team-blue",
		TaskID:      "task-1",
		Topic:       "CVE context is contradictory",
		Trigger:     domain.SummonTriggerStall,
		OpenedBy:    "triage",
		Signals:     stalledSignals(),
		Brief:       domain.RoomBrief{Problem: "conflicting patch versions", Ask: "which source wins"},
	})
	if err != nil {
		t.Fatalf("Summon() error = %v", err)
	}

	// 3 participants + 1 synthesizer: cost is O(N), not O(N x rounds).
	if len(contributor.calls) != 4 {
		t.Fatalf("model calls = %d, want 4 (3 participants + 1 synthesis)", len(contributor.calls))
	}
	participants := 0
	synthesizers := 0
	for _, call := range contributor.calls {
		switch call.Role {
		case TurnParticipant:
			participants++
			if len(call.Replies) != 0 {
				t.Fatal("participants must not see other agents' replies")
			}
			if call.Brief.Problem == "" {
				t.Fatal("participants must receive the brief")
			}
		case TurnSynthesizer:
			synthesizers++
			if len(call.Replies) != 3 {
				t.Fatalf("synthesizer saw %d replies, want 3", len(call.Replies))
			}
		}
	}
	if participants != 3 || synthesizers != 1 {
		t.Fatalf("participants=%d synthesizers=%d", participants, synthesizers)
	}
	if outcome.Decision.Outcome != "proceed" {
		t.Fatalf("Decision.Outcome = %q, want proceed", outcome.Decision.Outcome)
	}
	if outcome.Decision.NextOwner != "triage" {
		t.Fatalf("NextOwner = %q", outcome.Decision.NextOwner)
	}
	if outcome.TokensUsed != 400 {
		t.Fatalf("TokensUsed = %d, want 400", outcome.TokensUsed)
	}
	if repo.closedStatus != domain.RoomStatusClosed {
		t.Fatalf("status = %q, want closed", repo.closedStatus)
	}
}

func TestSummonPrefersCriticAsSynthesizer(t *testing.T) {
	repo := newFakeRoomRepo()
	contributor := &fakeContributor{tokens: 10}
	service := newTestService(repo, &fakeTeamRepo{members: threeMembers()}, contributor)

	if _, err := service.Summon(context.Background(), SummonRequest{
		WorkspaceID: "ws-1",
		TeamID:      "team-blue",
		Trigger:     domain.SummonTriggerUser,
		OpenedBy:    "user",
		Brief:       domain.RoomBrief{Problem: "phase one done"},
	}); err != nil {
		t.Fatalf("Summon() error = %v", err)
	}

	last := contributor.calls[len(contributor.calls)-1]
	if last.Role != TurnSynthesizer || last.AgentKey != "critic" {
		t.Fatalf("synthesizer = %s/%s, want critic", last.AgentKey, last.Role)
	}
}

func TestSummonStopsWhenTokenBudgetIsExhausted(t *testing.T) {
	repo := newFakeRoomRepo()
	contributor := &fakeContributor{tokens: 100}
	service := newTestService(repo, &fakeTeamRepo{members: threeMembers()}, contributor)

	outcome, err := service.Summon(context.Background(), SummonRequest{
		WorkspaceID: "ws-1",
		TeamID:      "team-blue",
		Trigger:     domain.SummonTriggerUser,
		OpenedBy:    "user",
		Brief:       domain.RoomBrief{Problem: "cheap room"},
		Budget: domain.RoomBudget{
			MaxParticipants:  3,
			MaxRounds:        1,
			MaxTokensPerTurn: 1024,
			MaxTotalTokens:   150,
		},
	})
	if err != nil {
		t.Fatalf("Summon() error = %v", err)
	}

	if outcome.Stopped != "budget" {
		t.Fatalf("Stopped = %q, want budget", outcome.Stopped)
	}
	if outcome.Decision.Outcome != "escalate_human" {
		t.Fatalf("Decision.Outcome = %q, want escalate_human", outcome.Decision.Outcome)
	}
	if len(contributor.calls) >= 4 {
		t.Fatalf("model calls = %d; the budget must cut the room short", len(contributor.calls))
	}
}

func TestSummonSkipsFailedAgentAndStillDecides(t *testing.T) {
	repo := newFakeRoomRepo()
	contributor := &fakeContributor{tokens: 10, failAgent: "intel"}
	service := newTestService(repo, &fakeTeamRepo{members: threeMembers()}, contributor)

	outcome, err := service.Summon(context.Background(), SummonRequest{
		WorkspaceID: "ws-1",
		TeamID:      "team-blue",
		Trigger:     domain.SummonTriggerUser,
		OpenedBy:    "user",
		Brief:       domain.RoomBrief{Problem: "one agent down"},
	})
	if err != nil {
		t.Fatalf("Summon() error = %v", err)
	}
	if outcome.Decision.Outcome != "proceed" {
		t.Fatalf("Decision.Outcome = %q, want proceed", outcome.Decision.Outcome)
	}

	found := false
	for _, event := range repo.events {
		if event.Kind == domain.RoomEventAgentSkipped && event.Actor == "intel" {
			found = true
		}
	}
	if !found {
		t.Fatal("a failed agent must be recorded as skipped, not silently dropped")
	}
}

func TestSummonRejectsUnjustifiedAgentRequest(t *testing.T) {
	repo := newFakeRoomRepo()
	service := newTestService(repo, &fakeTeamRepo{members: threeMembers()}, &fakeContributor{})

	_, err := service.Summon(context.Background(), SummonRequest{
		WorkspaceID:    "ws-1",
		TeamID:         "team-blue",
		Trigger:        domain.SummonTriggerAgent,
		AgentRequested: true,
		OpenedBy:       "triage",
		Brief:          domain.RoomBrief{Problem: "I would rather not"},
		Signals:        domain.StallSignals{StepsUsed: 1, StepBudget: 12},
	})
	if err == nil {
		t.Fatal("a self-reported block without corroboration must be rejected")
	}
}

func TestSummonRejectsDuplicateEscalationForSameTask(t *testing.T) {
	repo := newFakeRoomRepo()
	service := newTestService(repo, &fakeTeamRepo{members: threeMembers()}, &fakeContributor{tokens: 1})
	req := SummonRequest{
		WorkspaceID: "ws-1",
		TeamID:      "team-blue",
		TaskID:      "task-1",
		Trigger:     domain.SummonTriggerStall,
		OpenedBy:    "triage",
		Signals:     stalledSignals(),
		Brief:       domain.RoomBrief{Problem: "stuck"},
	}
	if _, err := service.Summon(context.Background(), req); err != nil {
		t.Fatalf("first Summon() error = %v", err)
	}
	// Simulate the escalation still being open (first room did not resolve it).
	repo.escalationOpen = true
	if _, err := service.Summon(context.Background(), req); err == nil {
		t.Fatal("a second room for the same open escalation must be rejected")
	}
}

func TestSummonRejectsWhenTeamHasNoEnabledMembers(t *testing.T) {
	repo := newFakeRoomRepo()
	members := []domain.TeamMember{{AgentKey: "triage", Duty: "triage", Enabled: false}}
	service := newTestService(repo, &fakeTeamRepo{members: members}, &fakeContributor{})

	_, err := service.Summon(context.Background(), SummonRequest{
		WorkspaceID: "ws-1",
		TeamID:      "team-empty",
		Trigger:     domain.SummonTriggerUser,
		OpenedBy:    "user",
		Brief:       domain.RoomBrief{Problem: "nobody home"},
	})
	if err == nil {
		t.Fatal("a team with no enabled members must be rejected")
	}
}

func TestSummonFallsBackToHumanWhenSynthesisIsNotStructured(t *testing.T) {
	repo := newFakeRoomRepo()
	contributor := &fakeContributor{tokens: 10, decision: "I think we should probably retry, but I am not sure."}
	service := newTestService(repo, &fakeTeamRepo{members: threeMembers()}, contributor)

	outcome, err := service.Summon(context.Background(), SummonRequest{
		WorkspaceID: "ws-1",
		TeamID:      "team-blue",
		Trigger:     domain.SummonTriggerUser,
		OpenedBy:    "user",
		Brief:       domain.RoomBrief{Problem: "prose only"},
	})
	if err != nil {
		t.Fatalf("Summon() error = %v", err)
	}
	if outcome.Decision.Outcome != "escalate_human" {
		t.Fatalf("Decision.Outcome = %q, want escalate_human for unstructured output", outcome.Decision.Outcome)
	}
	if repo.closedStatus != domain.RoomStatusEscalated {
		t.Fatalf("status = %q, want escalated", repo.closedStatus)
	}
}

func TestSummonWrapsRoleScopedContext(t *testing.T) {
	repo := newFakeRoomRepo()
	contributor := &fakeContributor{tokens: 10}
	service := newTestService(repo, &fakeTeamRepo{members: threeMembers()}, contributor)

	if _, err := service.Summon(context.Background(), SummonRequest{
		WorkspaceID: "ws-1",
		TeamID:      "team-blue",
		Topic:       strings.Repeat("x", 300),
		Trigger:     domain.SummonTriggerUser,
		OpenedBy:    "user",
		Brief:       domain.RoomBrief{Problem: "long topic"},
	}); err != nil {
		t.Fatalf("Summon() error = %v", err)
	}
	if len(repo.room.Topic) > 200 {
		t.Fatalf("topic length = %d, want it truncated", len(repo.room.Topic))
	}
	for _, call := range contributor.calls {
		if call.ModelRole == "" && call.Role == TurnParticipant {
			t.Fatalf("participant %q lost its model role binding", call.AgentKey)
		}
	}
}
