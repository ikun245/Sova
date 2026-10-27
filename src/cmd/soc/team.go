package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"soc/agent/internal/agent"
	"soc/agent/internal/domain"
	"soc/agent/internal/exec"
	"soc/agent/internal/llm"
	"soc/agent/internal/platform"
	"soc/agent/internal/store"
)

// runTeam drives the fixed roster over one engagement.
//
// The difference from `soc hunt` is who decides what to do next across duties:
// hunt runs one duty you name; team has a planner choose the steps, workers
// produce findings, a critic decides what counts, and a reporter writes it up.
// The gates are identical, because every duty ends in the same exec.Runner.
func runTeam(args []string) error {
	flags := flag.NewFlagSet("team", flag.ContinueOnError)
	scopeID := flags.String("scope", "", "stored scope id (required)")
	target := flags.String("target", "", "target host (required)")
	port := flags.Int("port", 443, "target port")
	goal := flags.String("goal", "", "engagement goal (required)")
	taskID := flags.String("task", "", "existing task id for findings; created if empty")
	approval := flags.String("approval", "", "approval id for a parked action")
	resumePath := flags.String("resume", "", "parked team file from a previous run")
	parkPath := flags.String("park-to", "", "where to write the parked team state")
	if err := flags.Parse(args); err != nil {
		return err
	}

	parked, err := loadParkedTeam(*resumePath)
	if err != nil {
		return err
	}
	if parked != nil {
		if *approval == "" {
			return fmt.Errorf("resuming needs --approval <id>; the parked action is %s",
				strings.Join(parked.Argv, " "))
		}
		// Take identity from the parked file so a resume cannot be pointed at a
		// different engagement.
		*scopeID = parked.ScopeID
		*target = parked.Target
		*port = parked.Port
		*goal = parked.Goal
		*taskID = parked.TaskID
	}
	if *scopeID == "" || *target == "" || *goal == "" {
		return errors.New("usage: soc team --scope <id> --target <host> --goal \"...\"")
	}

	config, err := platform.LoadConfig()
	if err != nil {
		return err
	}
	models, err := platform.LoadModelsConfig()
	if errors.Is(err, platform.ErrModelsNotConfigured) {
		return errors.New("no models configured: set SOC_MODELS_CONFIG to a models YAML file")
	}
	if err != nil {
		return err
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	database, err := store.OpenPostgres(ctx, config.PostgresDSN)
	if err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	defer database.Close()

	record, err := database.GetScope(ctx, *scopeID)
	if err != nil {
		return fmt.Errorf("load scope: %w", err)
	}
	if !record.Active(time.Now()) {
		return errors.New("the scope is revoked or expired; this run would be unauthorized")
	}

	// A task row is required because findings reference it. Creating one here
	// means `soc team` leaves the same durable trail an API-driven engagement
	// would, instead of findings that belong to nothing.
	if *taskID == "" {
		created, err := createEngagementTask(ctx, database, *goal, record.Scope)
		if err != nil {
			return err
		}
		*taskID = created
	}

	runner := exec.NewRunner(exec.Policy{
		Ceiling:  record.Scope.MaxRisk,
		AskAbove: domain.RiskLight,
	}, record.Scope, storeAuditor{database: database})
	runner.Approvals = database
	runner.Backend = backendFor(config)

	tools, entries := agentTools(runner)
	registry := llm.NewRegistry(models)

	// runAgent resolves the duty's model, filters its tools by the engagement
	// ceiling, and runs one bounded loop. Every duty shares this path, so a
	// duty cannot acquire a capability the others lack.
	runAgent := func(ctx context.Context, duty agent.Duty, input string) (agent.RunResult, error) {
		spec, err := agent.SpecFor(duty, record.Scope.MaxRisk, entries)
		if err != nil {
			return agent.RunResult{}, err
		}
		client, resolved, err := registry.ForRole(spec.ModelRole)
		if err != nil {
			return agent.RunResult{}, fmt.Errorf("resolve model role %q: %w", spec.ModelRole, err)
		}

		system := agent.SystemPrompt(spec, record.Scope, agentToolDocs(tools, spec.Tools), time.Now().UTC().Format(time.RFC3339))
		loop := agent.Loop{
			LLM:        client,
			Model:      resolved.ModelID,
			Spec:       spec,
			Tools:      tools,
			System:     system,
			ApprovalID: *approval,
		}
		loop.ResumeMessages = []domain.Message{{Role: "user", Content: input}}

		fmt.Printf("\n=== %s (model %s, tools %s) ===\n", duty, resolved.ModelID, spec.ToolWhitelist())
		loop.OnStep = func(step agent.Step) {
			line := fmt.Sprintf("  [%02d] %-14s %-13s", step.Index, step.Tool, step.Code)
			if step.Args != "" {
				line += " " + step.Args
			}
			fmt.Println(line)
		}
		return loop.Run(ctx)
	}

	// settleAgent is the wrap-up phase. It shares the duty's model and tools but
	// gets a small turn budget: its only job is to write back what the worker had
	// already found before its exploration budget ran out. Without it those
	// findings are lost with the process and the next round starts over.
	settleAgent := func(ctx context.Context, duty agent.Duty, input string) (agent.RunResult, error) {
		spec, err := agent.SpecFor(duty, record.Scope.MaxRisk, entries)
		if err != nil {
			return agent.RunResult{}, err
		}
		spec.MaxSteps = 3
		spec.MaxTokens = 8000

		client, resolved, err := registry.ForRole(spec.ModelRole)
		if err != nil {
			return agent.RunResult{}, fmt.Errorf("resolve model role %q: %w", spec.ModelRole, err)
		}
		system := agent.SystemPrompt(spec, record.Scope, agentToolDocs(tools, spec.Tools), time.Now().UTC().Format(time.RFC3339))
		loop := agent.Loop{
			LLM:            client,
			Model:          resolved.ModelID,
			Spec:           spec,
			Tools:          tools,
			System:         system,
			ResumeMessages: []domain.Message{{Role: "user", Content: input}},
		}
		fmt.Printf("  --- settlement (%s, %d steps) ---\n", duty, spec.MaxSteps)
		return loop.Run(ctx)
	}

	orchestrator := agent.TeamOrchestrator{
		RunAgent:    runAgent,
		SettleAgent: settleAgent,
		Findings:    database,
		TaskID:      *taskID,
		Target:      fmt.Sprintf("%s:%d", *target, *port),
		Budget:      agent.DefaultTeamBudget(),
		ApprovalID:  *approval,
		OnStep:      func(line string) { fmt.Println("· " + line) },
	}
	if parked != nil {
		orchestrator.ResumeRound = parked.ResumeRound
		orchestrator.ResumeFrom = parked.ResumeFrom
		orchestrator.ResumeHistory = parked.History
		orchestrator.ResumePlan = parked.Plan
		orchestrator.ResumeAttempts = parked.Attempts

		// The task is sitting in waiting_approval from the previous process; move
		// it back to running before dispatching work, so a concurrent viewer of
		// GET /tasks never sees "waiting_approval" while work is actually happening.
		if err := database.SetTaskStatus(ctx, *taskID, domain.TaskStatusRunning); err != nil {
			return fmt.Errorf("mark task running before resume: %w", err)
		}
		resumedPayload, _ := json.Marshal(map[string]any{
			"approval_id":  *approval,
			"round":        parked.ResumeRound,
			"intent_index": parked.ResumeFrom,
		})
		if err := database.AppendTaskEvent(ctx, domain.TaskEvent{
			TaskID:  *taskID,
			Kind:    "task_resumed",
			Payload: resumedPayload,
		}); err != nil {
			return fmt.Errorf("append resume event: %w", err)
		}
	}

	fmt.Printf("task    %s\n", *taskID)
	fmt.Printf("scope   %s (ticket %s, max_risk %s)\n", record.Scope.ID, record.Scope.TicketID, record.Scope.MaxRisk)
	fmt.Printf("target  %s:%d\n", *target, *port)
	fmt.Printf("goal    %s\n", *goal)

	outcome, runErr := orchestrator.Run(ctx, *goal)

	fmt.Printf("\n--- team stop: %s ---\n", outcome.Stop)
	fmt.Printf("steps=%d tokens=%d duration=%s\n", outcome.Steps, outcome.Tokens, outcome.Duration.Round(time.Millisecond))
	fmt.Printf("findings: recorded=%d accepted=%d\n", len(outcome.Findings), len(outcome.Accepted))

	if outcome.Report != "" {
		fmt.Printf("\n%s\n", outcome.Report)
	}

	if outcome.Stop == agent.StopApproval && outcome.Pending != nil {
		path := *parkPath
		if path == "" {
			path = *resumePath
		}
		if path == "" {
			path = "team-parked.json"
		}
		state := parkedTeam{
			ScopeID:     record.Scope.ID,
			Target:      *target,
			Port:        *port,
			Goal:        *goal,
			TaskID:      *taskID,
			Tool:        outcome.Pending.Tool,
			Argv:        outcome.Pending.Argv,
			Risk:        outcome.Pending.Risk,
			ResumeFrom:  outcome.PendingIndex,
			ResumeRound: outcome.PendingRound,
			History:     outcome.PendingHistory,
			Plan:        outcome.Plan,
			Attempts:    outcome.Attempts,
		}
		if err := writeParkedTeam(path, state); err != nil {
			return err
		}

		// Mirror the park server-side: a human approving through the API, or an
		// operator watching GET /tasks, must be able to see that this task is
		// stuck on one exact action, not just infer it from a silent CLI process.
		checkpoint, err := json.Marshal(state)
		if err != nil {
			return fmt.Errorf("encode parked team state: %w", err)
		}
		if err := database.SaveCheckpoint(ctx, *taskID, checkpoint); err != nil {
			return fmt.Errorf("save parked team checkpoint: %w", err)
		}
		if err := database.SetTaskStatus(ctx, *taskID, domain.TaskStatusWaitingApproval); err != nil {
			return fmt.Errorf("mark task waiting for approval: %w", err)
		}
		requestedPayload, _ := json.Marshal(map[string]any{
			"tool":         outcome.Pending.Tool,
			"argv":         outcome.Pending.Argv,
			"risk":         outcome.Pending.Risk,
			"target":       outcome.Pending.Target,
			"round":        outcome.PendingRound,
			"intent_index": outcome.PendingIndex,
		})
		if err := database.AppendTaskEvent(ctx, domain.TaskEvent{
			TaskID:  *taskID,
			Kind:    "approval_requested",
			Payload: requestedPayload,
		}); err != nil {
			return fmt.Errorf("append approval_requested event: %w", err)
		}

		fmt.Printf("\n已暂停，等待人工审批（第 %d 步）。\n", outcome.PendingIndex+1)
		fmt.Printf("审批绑定 argv：%s\n", strings.Join(outcome.Pending.Argv, " "))
		fmt.Printf("批准后恢复：soc team --resume %s --approval <id>\n", path)
	}

	if outcome.Stop != agent.StopApproval {
		if err := finalizeTeamTask(ctx, database, *taskID, outcome); err != nil {
			return fmt.Errorf("record final task status: %w", err)
		}
	}

	if runErr != nil {
		return fmt.Errorf("team run failed: %w", runErr)
	}
	return nil
}

// finalizeTeamTask records the terminal outcome of a run that did not park on
// an approval: goal met is success, a transport/planner failure is failed, and
// budget/stall with the goal unmet needs a human to decide whether to extend it
// (the same meaning waiting_review already carries for triage).
func finalizeTeamTask(ctx context.Context, database *store.Postgres, taskID string, outcome agent.TeamOutcome) error {
	var status domain.TaskStatus
	switch outcome.Stop {
	case agent.StopVerdict:
		status = domain.TaskStatusSucceeded
	case agent.StopFatal:
		status = domain.TaskStatusFailed
	default: // StopBudget, StopStall
		status = domain.TaskStatusWaitingReview
	}

	payload, _ := json.Marshal(map[string]any{
		"stop":        outcome.Stop,
		"message":     outcome.Message,
		"goal_met":    outcome.GoalMet,
		"goal_reason": outcome.GoalReason,
		"steps":       outcome.Steps,
		"tokens":      outcome.Tokens,
	})
	if err := database.AppendTaskEvent(ctx, domain.TaskEvent{
		TaskID:  taskID,
		Kind:    "task_" + string(status),
		Payload: payload,
	}); err != nil {
		return err
	}
	return database.SetTaskStatus(ctx, taskID, status)
}

// createEngagementTask makes the durable row findings hang off. It records the
// engagement goal in the checkpoint so a reviewer can see what was asked.
func createEngagementTask(ctx context.Context, database *store.Postgres, goal string, scope domain.TargetScope) (string, error) {
	taskID := fmt.Sprintf("engage-%d", time.Now().UnixNano())
	checkpoint, err := json.Marshal(map[string]string{
		"goal":      goal,
		"scope_id":  scope.ID,
		"ticket_id": scope.TicketID,
	})
	if err != nil {
		return "", err
	}
	task, err := database.CreateTask(ctx, domain.Task{
		ID:         taskID,
		TenantID:   domain.LocalTenantID,
		Status:     domain.TaskStatusRunning,
		Checkpoint: checkpoint,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("create engagement task: %w", err)
	}
	return task.ID, nil
}

// parkedTeam is the on-disk state of a team run awaiting a human. It is a file
// rather than a row so a single-chair engagement needs no extra schema; moving
// it into the task tables is the next step for multi-worker use.
type parkedTeam struct {
	ScopeID     string   `json:"scope_id"`
	Target      string   `json:"target"`
	Port        int      `json:"port"`
	Goal        string   `json:"goal"`
	TaskID      string   `json:"task_id"`
	Tool        string   `json:"tool"`
	Argv        []string `json:"argv"`
	Risk        string   `json:"risk"`
	ResumeFrom  int      `json:"resume_from"`
	ResumeRound int      `json:"resume_round"`
	// History is the parked worker's transcript, so resuming does not repeat
	// calls that already produced results.
	History string `json:"history,omitempty"`
	// Plan is the exact plan the parked round parked on. Resuming must reuse it:
	// a fresh plan would reorder the intents and ResumeFrom would point elsewhere.
	Plan []agent.PlannedStep `json:"plan,omitempty"`
	// Attempts is the planner's memory across rounds; it must survive a resume or
	// the next round would re-dispatch work that was already done.
	Attempts []agent.Attempt `json:"attempts,omitempty"`
}

func loadParkedTeam(path string) (*parkedTeam, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read parked team %s: %w", path, err)
	}
	var state parkedTeam
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("parked team %s is not valid JSON: %w", path, err)
	}
	return &state, nil
}

func writeParkedTeam(path string, state parkedTeam) error {
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0o600)
}
