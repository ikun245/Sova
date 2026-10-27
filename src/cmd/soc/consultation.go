package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"

	"soc/agent/internal/domain"
	"soc/agent/internal/llm"
	"soc/agent/internal/platform"
	"soc/agent/internal/queue"
	"soc/agent/internal/room"
	"soc/agent/internal/store"
)

// agentRuntime holds the optional model-backed pieces. A nil runtime is a
// supported mode: the worker still drains intents, it just cannot judge alerts
// or summon a team.
type agentRuntime struct {
	executor     queue.Executor
	consultation *room.TaskConsultator
}

// buildAgentRuntime wires triage execution and team consultation from the same
// model registry, so both use one set of adapters and one cost surface.
func buildAgentRuntime(database *store.Postgres) (*agentRuntime, error) {
	models, err := platform.LoadModelsConfig()
	if errors.Is(err, platform.ErrModelsNotConfigured) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("load models config: %w", err)
	}

	// The workspace decides which team is summoned. Local mode has exactly one
	// workspace, so it comes from configuration rather than a lookup.
	workspaceID := os.Getenv("SOC_WORKSPACE_ID")
	if workspaceID == "" {
		workspaceID = "default"
	}

	registry := llm.NewRegistry(models)
	floor := confidenceFloor()

	slog.Info("agent runtime enabled",
		"workspace", workspaceID, "roles", len(models.Roles), "confidence_floor", floor)

	return &agentRuntime{
		executor: queue.NewTriageExecutor(registry, string(domain.RoleTriage), floor),
		consultation: room.NewTaskConsultator(
			room.NewService(database, database, room.NewLLMContributor(registry), room.DefaultPolicy()),
			database, workspaceID, "worker"),
	}, nil
}

// confidenceFloor reads the review threshold, defaulting to the design value.
// A malformed value falls back rather than blocking startup, but it logs so the
// misconfiguration is visible.
func confidenceFloor() float64 {
	raw := os.Getenv("SOC_CONFIDENCE_FLOOR")
	if raw == "" {
		return 0.75
	}
	value, err := strconv.ParseFloat(raw, 64)
	if err != nil || value <= 0 || value > 1 {
		slog.Warn("ignoring invalid SOC_CONFIDENCE_FLOOR", "value", raw)
		return 0.75
	}
	return value
}

// compile-time guards so a signature change in queue or room fails here
// instead of at the wiring site.
var (
	_ queue.Executor = (*queue.TriageExecutor)(nil)
	_ interface {
		SummonForTask(ctx context.Context, taskID string, signals domain.StallSignals, topic string) (string, error)
	} = (*room.TaskConsultator)(nil)
)
