package room

import (
	"context"
	"fmt"

	"soc/agent/internal/domain"
)

// TaskConsultator adapts the room service to the queue package's narrow
// Consultator port. It picks the team from the task's workspace and builds the
// brief from the agent's stall signals, so the handler never constructs prompts.
type TaskConsultator struct {
	service     *Service
	teams       domain.TeamRepository
	workspaceID string
	openedBy    string
}

func NewTaskConsultator(service *Service, teams domain.TeamRepository, workspaceID, openedBy string) *TaskConsultator {
	return &TaskConsultator{
		service:     service,
		teams:       teams,
		workspaceID: workspaceID,
		openedBy:    openedBy,
	}
}

// SummonForTask opens a room for a stuck task and returns a one-line summary of
// the decision. An error means no room was opened, so the caller keeps its
// existing failure handling.
func (c *TaskConsultator) SummonForTask(
	ctx context.Context,
	taskID string,
	signals domain.StallSignals,
	topic string,
) (string, error) {
	teams, err := c.teams.ListTeams(ctx, c.workspaceID)
	if err != nil {
		return "", fmt.Errorf("room: list teams: %w", err)
	}
	if len(teams) == 0 {
		return "", fmt.Errorf("room: workspace %q has no team to consult", c.workspaceID)
	}

	brief := domain.RoomBrief{
		Problem: topic,
		Missing: signalsReasons(signals),
		Ask:     "这个任务卡住了，请判断下一步该怎么走；若证据不足请直接建议转人工。",
	}

	outcome, err := c.service.Summon(ctx, SummonRequest{
		WorkspaceID: c.workspaceID,
		TeamID:      teams[0].ID,
		TaskID:      taskID,
		Topic:       topic,
		Trigger:     domain.SummonTriggerStall,
		OpenedBy:    c.openedBy,
		Signals:     signals,
		Brief:       brief,
	})
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("room %s: %s (next owner: %s, tokens: %d)",
		outcome.RoomID, outcome.Decision.Outcome, outcome.Decision.NextOwner, outcome.TokensUsed), nil
}

// signalsReasons turns objective stall signals into the brief's "missing"
// list. Using the computed reasons keeps the brief factual rather than letting
// the stuck agent describe its own problem.
func signalsReasons(signals domain.StallSignals) []string {
	reasons := signals.Evaluate()
	if len(reasons) == 0 {
		return nil
	}
	return reasons
}
