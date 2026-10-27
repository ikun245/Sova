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
	"unicode/utf8"

	"soc/agent/internal/agent"
	"soc/agent/internal/domain"
	"soc/agent/internal/exec"
	"soc/agent/internal/llm"
	"soc/agent/internal/platform"
	"soc/agent/internal/store"
)

// runHunt drives one agent duty against an authorized target.
//
// The difference from `soc probe` / `soc web` is who decides the next step: the
// model does, inside a bounded loop. The gates are identical because both paths
// end in the same exec.Runner.
//
// An approval does not fail the run: it parks it. The exact binding is written
// to a file, a human approves it through the API, and `--resume` continues from
// the parked call. A model that retried an approval wall would burn its whole
// budget producing identical audit rows.
func runHunt(args []string) error {
	flags := flag.NewFlagSet("hunt", flag.ContinueOnError)
	scopeID := flags.String("scope", "", "stored scope id (required)")
	target := flags.String("target", "", "target host, e.g. a CTF hostname")
	port := flags.Int("port", 443, "target port")
	dutyName := flags.String("duty", string(agent.DutyWeb), "duty: plan, recon, web, exploit, critic, report")
	goal := flags.String("goal", "", "what this run must accomplish")
	approval := flags.String("approval", "", "approval id for the parked action")
	resumePath := flags.String("resume", "", "path to a parked run file (from a previous --approval stop)")
	parkPath := flags.String("park-to", "", "where to write the parked request; defaults next to the workspace")
	showSteps := flags.Bool("steps", true, "stream each tool call as it happens")
	if err := flags.Parse(args); err != nil {
		return err
	}

	parked, err := loadParked(*resumePath)
	if err != nil {
		return err
	}
	if parked != nil {
		if *approval == "" {
			return fmt.Errorf("resuming needs --approval <id>; the parked action is %s %s",
				parked.Tool, strings.Join(parked.Argv, " "))
		}
		// The parked run carries its own scope and duty, so a resume cannot be
		// redirected at a different engagement.
		if *scopeID == "" {
			*scopeID = parked.ScopeID
		}
		if *target == "" {
			*target = parked.Target
		}
		if *dutyName == string(agent.DutyWeb) {
			*dutyName = parked.Duty
		}
		if *goal == "" {
			*goal = parked.Goal
		}
	}

	if *scopeID == "" || *target == "" {
		return errors.New("usage: soc hunt --scope <id> --target <host> --goal \"...\" [--duty web]")
	}
	duty := agent.Duty(*dutyName)

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

	runner := exec.NewRunner(exec.Policy{
		Ceiling:  record.Scope.MaxRisk,
		AskAbove: domain.RiskLight,
	}, record.Scope, storeAuditor{database: database})
	runner.Approvals = database
	runner.Backend = backendFor(config)

	tools, entries := agentTools(runner)
	spec, err := agent.SpecFor(duty, record.Scope.MaxRisk, entries)
	if err != nil {
		return err
	}

	client, resolved, err := llm.NewRegistry(models).ForRole(spec.ModelRole)
	if err != nil {
		return fmt.Errorf("resolve model role %q: %w", spec.ModelRole, err)
	}

	system := agent.SystemPrompt(spec, record.Scope, agentToolDocs(tools, spec.Tools), time.Now().UTC().Format(time.RFC3339))

	fmt.Printf("duty    %s\n", spec.Duty)
	fmt.Printf("model   %s (%s)\n", resolved.ModelID, spec.ModelRole)
	fmt.Printf("scope   %s (ticket %s, max_risk %s)\n", record.Scope.ID, record.Scope.TicketID, record.Scope.MaxRisk)
	fmt.Printf("target  %s:%d\n", *target, *port)
	fmt.Printf("tools   %s\n", spec.ToolWhitelist())
	fmt.Printf("budget  %d steps, %d tokens\n\n", spec.MaxSteps, spec.MaxTokens)

	task := fmt.Sprintf("目标：%s:%d\n\n本步骤要达成的目标：%s\n\n", *target, *port, *goal)
	if parked != nil {
		// Give the model the outcome of the action it was waiting on, so it
		// continues instead of repeating the same call.
		task += "上一轮因为需要人工审批而暂停，现在该动作已被批准并需要重新执行。\n" +
			"被暂停的调用是：" + parked.Tool + " " + string(parked.Arguments) + "\n"
	}

	loop := agent.Loop{
		LLM:        client,
		Model:      resolved.ModelID,
		Spec:       spec,
		Tools:      tools,
		System:     system,
		ApprovalID: *approval,
	}
	if parked != nil {
		loop.ResumeMessages = []domain.Message{{Role: "user", Content: parked.History}}
	}
	loop.ResumeMessages = append(loop.ResumeMessages, domain.Message{Role: "user", Content: task})

	if *showSteps {
		loop.OnStep = func(step agent.Step) {
			line := fmt.Sprintf("  [%02d] %-14s %-13s", step.Index, step.Tool, step.Code)
			if step.Args != "" {
				line += " " + step.Args
			}
			fmt.Println(line)
		}
	}

	result, runErr := loop.Run(ctx)
	fmt.Printf("\n--- stop: %s (%s) ---\n", result.Stop, result.Message)
	fmt.Printf("steps=%d tool_calls=%d tokens=%d duration=%s\n",
		len(result.Steps), result.ToolCalls, result.Tokens, result.Duration.Round(time.Millisecond))

	if result.Content != "" {
		fmt.Printf("\n%s\n", result.Content)
	}

	if result.Stop == agent.StopApproval && result.Pending != nil {
		path := *parkPath
		if path == "" {
			// Reuse the file that was resumed, so a second wall overwrites the
			// parked state instead of scattering hunt-parked.json everywhere.
			path = *resumePath
		}
		if path == "" {
			path = "hunt-parked.json"
		}
		state := parkedRun{
			ScopeID:   record.Scope.ID,
			Target:    *target,
			Duty:      string(duty),
			Goal:      *goal,
			Tool:      result.Pending.Tool,
			Argv:      result.Pending.Argv,
			Risk:      result.Pending.Risk,
			Arguments: result.Pending.Arguments,
			History:   historyText(result.Messages),
		}
		if err := writeParked(path, state); err != nil {
			return err
		}
		fmt.Printf("\n已暂停，等待人工审批。\n")
		fmt.Printf("审批绑定 argv：%s\n", strings.Join(result.Pending.Argv, " "))
		fmt.Printf("批准后恢复：soc hunt --resume %s --approval <id>\n", path)
	}

	if runErr != nil {
		return fmt.Errorf("agent run failed: %w", runErr)
	}
	return nil
}

// parkedRun is the on-disk state of a run waiting for a human. It lives in a
// file rather than the database so a single-chair engagement needs no schema.
type parkedRun struct {
	ScopeID   string          `json:"scope_id"`
	Target    string          `json:"target"`
	Duty      string          `json:"duty"`
	Goal      string          `json:"goal"`
	Tool      string          `json:"tool"`
	Argv      []string        `json:"argv"`
	Risk      string          `json:"risk"`
	Arguments json.RawMessage `json:"arguments"`
	History   string          `json:"history"`
}

func loadParked(path string) (*parkedRun, error) {
	if strings.TrimSpace(path) == "" {
		return nil, nil
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read parked run %s: %w", path, err)
	}
	var state parkedRun
	if err := json.Unmarshal(raw, &state); err != nil {
		return nil, fmt.Errorf("parked run %s is not valid JSON: %w", path, err)
	}
	return &state, nil
}

func writeParked(path string, state parkedRun) error {
	encoded, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, encoded, 0o600)
}

// historyText flattens the transcript so a resumed run keeps the facts it
// already established without replaying the full provider message structure.
func historyText(messages []domain.Message) string {
	const maxToolContent = 1200
	var b strings.Builder
	b.WriteString("上一轮的对话摘要：\n")
	for _, message := range messages {
		switch message.Role {
		case "assistant":
			if message.Content != "" {
				b.WriteString("助手：" + message.Content + "\n")
			}
			for _, call := range message.ToolCalls {
				b.WriteString("调用：" + call.Name + " " + string(call.Arguments) + "\n")
			}
		case "tool":
			content := message.Content
			if len(content) > maxToolContent {
				// Cut on a rune boundary: the transcript is Chinese, and slicing
				// bytes would produce invalid UTF-8 in the resumed prompt.
				cut := maxToolContent
				for cut > 0 && !utf8.RuneStart(content[cut]) {
					cut--
				}
				content = content[:cut] + "...(截断)"
			}
			b.WriteString("结果[" + message.Name + "]：" + content + "\n")
		}
	}
	return b.String()
}
