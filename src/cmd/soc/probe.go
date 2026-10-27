package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"strings"
	"time"

	"soc/agent/internal/domain"
	"soc/agent/internal/exec"
	"soc/agent/internal/platform"
	"soc/agent/internal/store"
)

// runProbe executes one scan tool against a target under a stored engagement
// scope.
//
// This is the manual counterpart to an agent calling the same tools: it exists
// so scope enforcement, approval, rate limiting and the result envelope can be
// exercised against a real target without waiting for orchestration to exist.
func runProbe(args []string) error {
	flags := flag.NewFlagSet("probe", flag.ContinueOnError)
	scopeID := flags.String("scope", "", "stored scope id (required)")
	toolName := flags.String("tool", "http_probe", "tool: dns_lookup, http_probe, port_scan, service_scan, web_enum")
	host := flags.String("host", "", "target host (required)")
	port := flags.Int("port", 443, "target port")
	path := flags.String("path", "/", "request path, for tools that fetch a page")
	approval := flags.String("approval", "", "approval id, required when the tool needs approval")
	timeout := flags.Duration("timeout", 60*time.Second, "execution timeout")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *scopeID == "" || *host == "" {
		return errors.New("usage: soc probe --scope <id> --host <target> [--tool name] [--port n] [--approval id]")
	}

	config, err := platform.LoadConfig()
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
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
		return errors.New("the scope is revoked or expired; a probe would be unauthorized")
	}

	// The engagement ceiling decides what the policy allows. Approvals are
	// checked against the same store the API writes, so a human decision made
	// in one place takes effect here.
	policy := exec.Policy{
		Ceiling:  record.Scope.MaxRisk,
		AskAbove: domain.RiskLight,
	}
	runner := exec.NewRunner(policy, record.Scope, storeAuditor{database: database})
	runner.Approvals = database
	runner.Backend = backendFor(config)

	tools := exec.Catalog(runner)
	var tool *exec.ScanTool
	for _, candidate := range tools {
		if candidate.Spec().Name == *toolName {
			tool = candidate
			break
		}
	}
	if tool == nil {
		names := make([]string, 0, len(tools))
		for _, candidate := range tools {
			names = append(names, candidate.Spec().Name)
		}
		return fmt.Errorf("unknown tool %q; available: %s", *toolName, strings.Join(names, ", "))
	}

	fmt.Printf("scope   %s (ticket %s, max_risk %s)\n", record.Scope.ID, record.Scope.TicketID, record.Scope.MaxRisk)
	fmt.Printf("target  %s:%d\n", *host, *port)
	fmt.Printf("tool    %s (risk %s)\n", tool.Spec().Name, tool.Spec().Risk)
	if runner.Limiter != nil {
		fmt.Printf("rate    %d/min (interval %s)\n", record.Scope.MaxRatePerMinute, runner.Limiter.Interval())
	}

	request, err := json.Marshal(map[string]any{"host": *host, "port": *port, "path": *path})
	if err != nil {
		return err
	}

	// Attach the approval to the runner's request by running the tool through a
	// small adapter, since the tool itself does not take an approval id.
	result := tool.InvokeWithApproval(ctx, request, *approval, *timeout)

	encoded, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(encoded))

	if !result.OK {
		return fmt.Errorf("probe failed: %s", result.Code)
	}
	return nil
}

// storeAuditor persists every decision so the probe leaves the same trail an
// agent would.
type storeAuditor struct {
	database *store.Postgres
}

func (a storeAuditor) Record(ctx context.Context, entry exec.AuditEntry) error {
	payload := map[string]any{
		"scope_id":    entry.ScopeID,
		"ticket_id":   entry.TicketID,
		"program":     entry.Program,
		"argv":        entry.Argv,
		"target":      entry.Target,
		"risk":        entry.Risk,
		"decision":    entry.Decision,
		"reason":      entry.Reason,
		"exit_code":   entry.ExitCode,
		"duration_ms": entry.Duration.Milliseconds(),
		"truncated":   entry.Truncated,
		"timed_out":   entry.TimedOut,
		"approval_id": entry.ApprovalID,
		"sandbox":     entry.Sandbox,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	// Probe runs do not belong to an agent task, so the event is keyed by the
	// scope instead of a task id.
	return a.database.AppendTaskEvent(ctx, domain.TaskEvent{
		TaskID:  "probe:" + entry.ScopeID,
		Kind:    "probe_" + string(entry.Decision),
		Payload: encoded,
	})
}
