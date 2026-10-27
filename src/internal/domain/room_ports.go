package domain

import (
	"context"
	"encoding/json"
)

// RoomRepository persists consultations. Event appends own their sequence
// number so callers never have to guess it.
type RoomRepository interface {
	CreateRoom(ctx context.Context, room Room, participants []RoomParticipant) (Room, error)
	GetRoom(ctx context.Context, roomID string) (Room, error)
	AppendRoomEvent(ctx context.Context, event RoomEvent) (RoomEvent, error)
	ListRoomEvents(ctx context.Context, roomID string) ([]RoomEvent, error)
	UpdateParticipant(ctx context.Context, roomID, agentKey, state string, tokensUsed int) error
	CloseRoom(ctx context.Context, roomID string, status RoomStatus, decision json.RawMessage) error
	// OpenEscalation creates the de-duplicating escalation record. It reports
	// false when the task already has an open escalation, so a retrying agent
	// cannot open a second room for the same wall.
	OpenEscalation(ctx context.Context, escalation Escalation) (Escalation, bool, error)
	ResolveEscalation(ctx context.Context, escalationID, roomID, status string) error
}

// TeamRepository reads team composition for a workspace.
type TeamRepository interface {
	CreateTeam(ctx context.Context, team Team, members []TeamMember) (Team, error)
	ListTeams(ctx context.Context, workspaceID string) ([]Team, error)
	ListTeamMembers(ctx context.Context, teamID string) ([]TeamMember, error)
}

type Team struct {
	ID          string `json:"id"`
	WorkspaceID string `json:"workspace_id"`
	Name        string `json:"name"`
	Kind        string `json:"kind"`
}

type TeamMember struct {
	ID         string `json:"id"`
	TeamID     string `json:"team_id"`
	AgentKey   string `json:"agent_key"`
	Duty       string `json:"duty"`
	ModelRole  string `json:"model_role"`
	TurnBudget int    `json:"turn_budget"`
	Enabled    bool   `json:"enabled"`
	Position   int    `json:"position"`
}
