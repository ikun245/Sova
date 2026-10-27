package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"soc/agent/internal/domain"
)

var ErrRoomNotFound = errors.New("room not found")

func (p *Postgres) CreateRoom(ctx context.Context, room domain.Room, participants []domain.RoomParticipant) (domain.Room, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Room{}, fmt.Errorf("begin room transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO rooms (id, workspace_id, team_id, task_id, topic, trigger, status, budget, opened_by)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), $5, $6, $7, $8, $9)`,
		room.ID, room.WorkspaceID, room.TeamID, room.TaskID, room.Topic,
		room.Trigger, room.Status, mustMarshal(room.Budget), room.OpenedBy,
	); err != nil {
		return domain.Room{}, fmt.Errorf("insert room: %w", err)
	}

	for _, participant := range participants {
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO room_participants (room_id, agent_key, duty, model_role, state)
			VALUES ($1, $2, $3, $4, $5)
			ON CONFLICT (room_id, agent_key) DO NOTHING`,
			room.ID, participant.AgentKey, participant.Duty, participant.ModelRole, participant.State,
		); err != nil {
			return domain.Room{}, fmt.Errorf("insert room participant %q: %w", participant.AgentKey, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return domain.Room{}, fmt.Errorf("commit room transaction: %w", err)
	}
	return p.GetRoom(ctx, room.ID)
}

func (p *Postgres) GetRoom(ctx context.Context, roomID string) (domain.Room, error) {
	var room domain.Room
	var budget []byte
	err := p.db.QueryRowContext(ctx, `
		SELECT id, workspace_id, COALESCE(team_id, ''), COALESCE(task_id, ''), topic, trigger, status,
		       budget, COALESCE(decision, '{}'::jsonb), opened_by, created_at, closed_at
		FROM rooms WHERE id = $1`, roomID,
	).Scan(&room.ID, &room.WorkspaceID, &room.TeamID, &room.TaskID, &room.Topic, &room.Trigger,
		&room.Status, &budget, &room.Decision, &room.OpenedBy, &room.CreatedAt, &room.ClosedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Room{}, ErrRoomNotFound
	}
	if err != nil {
		return domain.Room{}, fmt.Errorf("get room: %w", err)
	}
	if len(budget) > 0 {
		if err := json.Unmarshal(budget, &room.Budget); err != nil {
			return domain.Room{}, fmt.Errorf("decode room budget: %w", err)
		}
	}
	return room, nil
}

// AppendRoomEvent assigns the next sequence number under a room row lock so
// concurrent appenders cannot collide on UNIQUE (room_id, seq).
func (p *Postgres) AppendRoomEvent(ctx context.Context, event domain.RoomEvent) (domain.RoomEvent, error) {
	if event.SchemaVersion == 0 {
		event.SchemaVersion = 1
	}
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.RoomEvent{}, fmt.Errorf("begin room event transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	var lockedRoomID string
	if err := tx.QueryRowContext(ctx, `SELECT id FROM rooms WHERE id = $1 FOR UPDATE`, event.RoomID).
		Scan(&lockedRoomID); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.RoomEvent{}, ErrRoomNotFound
		}
		return domain.RoomEvent{}, fmt.Errorf("lock room for event: %w", err)
	}

	if err := tx.QueryRowContext(ctx, `
		SELECT COALESCE(MAX(seq), 0) + 1 FROM room_events WHERE room_id = $1`, event.RoomID,
	).Scan(&event.Seq); err != nil {
		return domain.RoomEvent{}, fmt.Errorf("next room event seq: %w", err)
	}

	err = tx.QueryRowContext(ctx, `
		INSERT INTO room_events (room_id, seq, kind, actor, schema_version, payload)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING at`,
		event.RoomID, event.Seq, event.Kind, event.Actor, event.SchemaVersion, []byte(event.Payload),
	).Scan(&event.At)
	if err != nil {
		return domain.RoomEvent{}, fmt.Errorf("append room event: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return domain.RoomEvent{}, fmt.Errorf("commit room event: %w", err)
	}
	return event, nil
}

func (p *Postgres) ListRoomEvents(ctx context.Context, roomID string) ([]domain.RoomEvent, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT room_id, seq, kind, actor, schema_version, payload, at
		FROM room_events WHERE room_id = $1 ORDER BY seq`, roomID)
	if err != nil {
		return nil, fmt.Errorf("query room events: %w", err)
	}
	defer rows.Close()

	events := make([]domain.RoomEvent, 0)
	for rows.Next() {
		var event domain.RoomEvent
		var payload []byte
		if err := rows.Scan(&event.RoomID, &event.Seq, &event.Kind, &event.Actor,
			&event.SchemaVersion, &payload, &event.At); err != nil {
			return nil, fmt.Errorf("scan room event: %w", err)
		}
		event.Payload = payload
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate room events: %w", err)
	}
	return events, nil
}

func (p *Postgres) UpdateParticipant(ctx context.Context, roomID, agentKey, state string, tokensUsed int) error {
	_, err := p.db.ExecContext(ctx, `
		UPDATE room_participants SET state = $3, tokens_used = $4
		WHERE room_id = $1 AND agent_key = $2`, roomID, agentKey, state, tokensUsed)
	if err != nil {
		return fmt.Errorf("update room participant: %w", err)
	}
	return nil
}

func (p *Postgres) CloseRoom(ctx context.Context, roomID string, status domain.RoomStatus, decision json.RawMessage) error {
	tag, err := p.db.ExecContext(ctx, `
		UPDATE rooms SET status = $2, decision = $3, closed_at = now()
		WHERE id = $1`, roomID, status, nullableJSON(decision))
	if err != nil {
		return fmt.Errorf("close room: %w", err)
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return fmt.Errorf("close room rows affected: %w", err)
	}
	if affected == 0 {
		return ErrRoomNotFound
	}
	return nil
}

// OpenEscalation returns created=false when the task already has an open
// escalation, which is how a retrying agent is stopped from opening a second
// room for the same problem.
func (p *Postgres) OpenEscalation(ctx context.Context, escalation domain.Escalation) (domain.Escalation, bool, error) {
	var stored domain.Escalation
	var reasons, signals []byte
	err := p.db.QueryRowContext(ctx, `
		INSERT INTO escalations (id, task_id, room_id, trigger, reasons, signals, status)
		VALUES ($1, $2, NULLIF($3, ''), $4, $5, $6, $7)
		ON CONFLICT (task_id) WHERE status IN ('open', 'in_room') DO NOTHING
		RETURNING id, task_id, COALESCE(room_id, ''), trigger, reasons, signals, status, created_at`,
		escalation.ID, escalation.TaskID, escalation.RoomID, escalation.Trigger,
		mustMarshal(escalation.Reasons), []byte(escalation.Signals), escalation.Status,
	).Scan(&stored.ID, &stored.TaskID, &stored.RoomID, &stored.Trigger, &reasons, &signals,
		&stored.Status, &stored.CreatedAt)

	if errors.Is(err, sql.ErrNoRows) {
		// Conflict: another escalation for this task is already open.
		existing, getErr := p.openEscalationForTask(ctx, escalation.TaskID)
		if getErr != nil {
			return domain.Escalation{}, false, getErr
		}
		return existing, false, nil
	}
	if err != nil {
		return domain.Escalation{}, false, fmt.Errorf("open escalation: %w", err)
	}

	stored.Reasons = decodeStrings(reasons)
	stored.Signals = signals
	return stored, true, nil
}

func (p *Postgres) openEscalationForTask(ctx context.Context, taskID string) (domain.Escalation, error) {
	var escalation domain.Escalation
	var reasons, signals []byte
	err := p.db.QueryRowContext(ctx, `
		SELECT id, task_id, COALESCE(room_id, ''), trigger, reasons, signals, status, created_at
		FROM escalations
		WHERE task_id = $1 AND status IN ('open', 'in_room')
		ORDER BY created_at DESC LIMIT 1`, taskID,
	).Scan(&escalation.ID, &escalation.TaskID, &escalation.RoomID, &escalation.Trigger,
		&reasons, &signals, &escalation.Status, &escalation.CreatedAt)
	if err != nil {
		return domain.Escalation{}, fmt.Errorf("load open escalation: %w", err)
	}
	escalation.Reasons = decodeStrings(reasons)
	escalation.Signals = signals
	return escalation, nil
}

func (p *Postgres) ResolveEscalation(ctx context.Context, escalationID, roomID, status string) error {
	_, err := p.db.ExecContext(ctx, `
		UPDATE escalations SET status = $2, room_id = COALESCE(NULLIF($3, ''), room_id), resolved_at = now()
		WHERE id = $1`, escalationID, status, roomID)
	if err != nil {
		return fmt.Errorf("resolve escalation: %w", err)
	}
	return nil
}

func (p *Postgres) CreateTeam(ctx context.Context, team domain.Team, members []domain.TeamMember) (domain.Team, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Team{}, fmt.Errorf("begin team transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO teams (id, workspace_id, name, kind) VALUES ($1, $2, $3, $4)`,
		team.ID, team.WorkspaceID, team.Name, team.Kind); err != nil {
		return domain.Team{}, fmt.Errorf("insert team: %w", err)
	}

	for position, member := range members {
		turnBudget := member.TurnBudget
		if turnBudget <= 0 {
			turnBudget = 1024
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO team_members (id, team_id, agent_key, duty, model_role, turn_budget, enabled, position)
			VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
			member.ID, team.ID, member.AgentKey, member.Duty, member.ModelRole, turnBudget, member.Enabled, position,
		); err != nil {
			return domain.Team{}, fmt.Errorf("insert team member %q: %w", member.AgentKey, err)
		}
	}

	if err := tx.Commit(); err != nil {
		return domain.Team{}, fmt.Errorf("commit team transaction: %w", err)
	}
	return team, nil
}

func (p *Postgres) ListTeams(ctx context.Context, workspaceID string) ([]domain.Team, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, workspace_id, name, kind FROM teams WHERE workspace_id = $1 ORDER BY name`, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("query teams: %w", err)
	}
	defer rows.Close()

	teams := make([]domain.Team, 0)
	for rows.Next() {
		var team domain.Team
		if err := rows.Scan(&team.ID, &team.WorkspaceID, &team.Name, &team.Kind); err != nil {
			return nil, fmt.Errorf("scan team: %w", err)
		}
		teams = append(teams, team)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate teams: %w", err)
	}
	return teams, nil
}

func (p *Postgres) ListTeamMembers(ctx context.Context, teamID string) ([]domain.TeamMember, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, team_id, agent_key, duty, model_role, turn_budget, enabled, position
		FROM team_members WHERE team_id = $1 ORDER BY position, agent_key`, teamID)
	if err != nil {
		return nil, fmt.Errorf("query team members: %w", err)
	}
	defer rows.Close()

	members := make([]domain.TeamMember, 0)
	for rows.Next() {
		var member domain.TeamMember
		if err := rows.Scan(&member.ID, &member.TeamID, &member.AgentKey, &member.Duty,
			&member.ModelRole, &member.TurnBudget, &member.Enabled, &member.Position); err != nil {
			return nil, fmt.Errorf("scan team member: %w", err)
		}
		members = append(members, member)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate team members: %w", err)
	}
	return members, nil
}

func mustMarshal(value any) []byte {
	encoded, err := json.Marshal(value)
	if err != nil {
		return []byte(`{}`)
	}
	return encoded
}

func decodeStrings(raw []byte) []string {
	var out []string
	if len(raw) == 0 {
		return out
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return out
	}
	return out
}
