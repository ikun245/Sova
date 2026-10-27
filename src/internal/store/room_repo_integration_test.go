//go:build integration

package store

import (
	"context"
	"encoding/json"
	"os"
	"sync"
	"testing"
	"time"

	"soc/agent/internal/domain"
)

func openRoomTestStore(t *testing.T) *Postgres {
	t.Helper()
	dsn := os.Getenv("SOC_PG_DSN")
	if dsn == "" {
		dsn = "postgres://soc:soc-local-dev-only@127.0.0.1:5432/soc?sslmode=disable"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	database, err := OpenPostgres(ctx, dsn)
	if err != nil {
		t.Skipf("PostgreSQL unavailable: %v", err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err := database.Migrate(); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	return database
}

func newWorkspace(t *testing.T, database *Postgres) string {
	t.Helper()
	ctx := context.Background()
	id := "ws-" + time.Now().Format("150405.000000000")
	if _, err := database.db.ExecContext(ctx,
		`INSERT INTO workspaces (id, tenant_id, name) VALUES ($1, $2, $3)`, id, domain.LocalTenantID, "test"); err != nil {
		t.Fatalf("insert workspace: %v", err)
	}
	t.Cleanup(func() {
		_, _ = database.db.ExecContext(context.Background(), `DELETE FROM workspaces WHERE id = $1`, id)
	})
	return id
}

func TestCreateRoomPersistsBudgetAndParticipants(t *testing.T) {
	database := openRoomTestStore(t)
	ctx := context.Background()
	workspaceID := newWorkspace(t, database)

	room, err := database.CreateRoom(ctx, domain.Room{
		ID:          "room-" + time.Now().Format("150405.000000000"),
		WorkspaceID: workspaceID,
		Topic:       "conflicting patch versions",
		Trigger:     domain.SummonTriggerStall,
		Status:      domain.RoomStatusSummoning,
		Budget:      domain.RoomBudget{MaxParticipants: 3, MaxRounds: 1, MaxTokensPerTurn: 1024, MaxTotalTokens: 9000},
		OpenedBy:    "triage",
	}, []domain.RoomParticipant{
		{RoomID: "r", AgentKey: "triage", Duty: "triage", ModelRole: "triage", State: domain.ParticipantInvited},
		{RoomID: "r", AgentKey: "critic", Duty: "critic", ModelRole: "triage", State: domain.ParticipantInvited},
	})
	if err != nil {
		t.Fatalf("CreateRoom() error = %v", err)
	}
	t.Cleanup(func() {
		_, _ = database.db.ExecContext(context.Background(), `DELETE FROM rooms WHERE id = $1`, room.ID)
	})

	if room.Budget.MaxTotalTokens != 9000 {
		t.Fatalf("budget = %+v, want it round-tripped", room.Budget)
	}
	var participants int
	if err := database.db.QueryRowContext(ctx,
		`SELECT count(*) FROM room_participants WHERE room_id = $1`, room.ID).Scan(&participants); err != nil {
		t.Fatalf("count participants: %v", err)
	}
	if participants != 2 {
		t.Fatalf("participants = %d, want 2", participants)
	}
}

func TestAppendRoomEventAssignsMonotonicSeqUnderConcurrency(t *testing.T) {
	database := openRoomTestStore(t)
	ctx := context.Background()
	workspaceID := newWorkspace(t, database)

	room, err := database.CreateRoom(ctx, domain.Room{
		ID:          "room-conc-" + time.Now().Format("150405.000000000"),
		WorkspaceID: workspaceID,
		Topic:       "concurrency",
		Trigger:     domain.SummonTriggerUser,
		Status:      domain.RoomStatusSummoning,
		Budget:      domain.DefaultRoomBudget(),
		OpenedBy:    "user",
	}, nil)
	if err != nil {
		t.Fatalf("CreateRoom() error = %v", err)
	}
	t.Cleanup(func() {
		_, _ = database.db.ExecContext(context.Background(), `DELETE FROM rooms WHERE id = $1`, room.ID)
	})

	const writers = 8
	var wg sync.WaitGroup
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := database.AppendRoomEvent(ctx, domain.RoomEvent{
				RoomID:  room.ID,
				Kind:    domain.RoomEventAgentTurn,
				Actor:   "agent",
				Payload: json.RawMessage(`{"text":"x"}`),
			}); err != nil {
				t.Errorf("AppendRoomEvent() error = %v", err)
			}
		}()
	}
	wg.Wait()

	events, err := database.ListRoomEvents(ctx, room.ID)
	if err != nil {
		t.Fatalf("ListRoomEvents() error = %v", err)
	}
	if len(events) != writers {
		t.Fatalf("events = %d, want %d", len(events), writers)
	}
	for i, event := range events {
		if event.Seq != i+1 {
			t.Fatalf("event %d has seq %d, want %d", i, event.Seq, i+1)
		}
	}
}

func TestOpenEscalationIsUniquePerOpenTask(t *testing.T) {
	database := openRoomTestStore(t)
	ctx := context.Background()
	taskID := "task-esc-" + time.Now().Format("150405.000000000")

	first, created, err := database.OpenEscalation(ctx, domain.Escalation{
		ID:      "esc-1-" + taskID,
		TaskID:  taskID,
		Trigger: domain.SummonTriggerStall,
		Reasons: []string{domain.ReasonStepBudget},
		Signals: json.RawMessage(`{"steps_used":12}`),
		Status:  "in_room",
	})
	if err != nil {
		t.Fatalf("first OpenEscalation() error = %v", err)
	}
	if !created {
		t.Fatal("first escalation should be created")
	}
	t.Cleanup(func() {
		_, _ = database.db.ExecContext(context.Background(), `DELETE FROM escalations WHERE task_id = $1`, taskID)
	})

	second, created, err := database.OpenEscalation(ctx, domain.Escalation{
		ID:      "esc-2-" + taskID,
		TaskID:  taskID,
		Trigger: domain.SummonTriggerStall,
		Reasons: []string{domain.ReasonStepBudget},
		Signals: json.RawMessage(`{"steps_used":12}`),
		Status:  "in_room",
	})
	if err != nil {
		t.Fatalf("second OpenEscalation() error = %v", err)
	}
	if created {
		t.Fatal("a second open escalation for the same task must be refused")
	}
	if second.ID != first.ID {
		t.Fatalf("returned escalation = %q, want the existing %q", second.ID, first.ID)
	}

	if err := database.ResolveEscalation(ctx, first.ID, "", "resolved"); err != nil {
		t.Fatalf("ResolveEscalation() error = %v", err)
	}
	_, created, err = database.OpenEscalation(ctx, domain.Escalation{
		ID:      "esc-3-" + taskID,
		TaskID:  taskID,
		Trigger: domain.SummonTriggerStall,
		Reasons: []string{domain.ReasonLowConfidence},
		Signals: json.RawMessage(`{}`),
		Status:  "in_room",
	})
	if err != nil {
		t.Fatalf("third OpenEscalation() error = %v", err)
	}
	if !created {
		t.Fatal("a new escalation should be allowed after the previous one resolved")
	}
}

func TestCreateTeamPersistsOrderedMembers(t *testing.T) {
	database := openRoomTestStore(t)
	ctx := context.Background()
	workspaceID := newWorkspace(t, database)
	teamID := "team-" + time.Now().Format("150405.000000000")

	if _, err := database.CreateTeam(ctx, domain.Team{
		ID:          teamID,
		WorkspaceID: workspaceID,
		Name:        "blue",
		Kind:        "blue",
	}, []domain.TeamMember{
		{ID: teamID + "-a", AgentKey: "triage", Duty: "triage", ModelRole: "triage", Enabled: true},
		{ID: teamID + "-b", AgentKey: "critic", Duty: "critic", ModelRole: "triage", Enabled: true, TurnBudget: 2048},
	}); err != nil {
		t.Fatalf("CreateTeam() error = %v", err)
	}
	t.Cleanup(func() {
		_, _ = database.db.ExecContext(context.Background(), `DELETE FROM teams WHERE id = $1`, teamID)
	})

	members, err := database.ListTeamMembers(ctx, teamID)
	if err != nil {
		t.Fatalf("ListTeamMembers() error = %v", err)
	}
	if len(members) != 2 {
		t.Fatalf("members = %d, want 2", len(members))
	}
	if members[0].AgentKey != "triage" || members[1].AgentKey != "critic" {
		t.Fatalf("members are not in configured order: %+v", members)
	}
	if members[1].TurnBudget != 2048 {
		t.Fatalf("TurnBudget = %d, want 2048", members[1].TurnBudget)
	}
	if members[0].TurnBudget != 1024 {
		t.Fatalf("default TurnBudget = %d, want 1024", members[0].TurnBudget)
	}
}
