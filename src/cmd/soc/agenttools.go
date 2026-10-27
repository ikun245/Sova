package main

import (
	"context"
	"encoding/json"
	"time"

	"soc/agent/internal/agent"
	"soc/agent/internal/domain"
	"soc/agent/internal/exec"
)

// toolAdapter bridges exec.Tool to agent.Tool. The two interfaces differ only in
// the name of the spec type, and Go has no covariant return types, so a thin
// adapter is cheaper than forcing one package to import the other's types.
type toolAdapter struct {
	name string
	spec exec.ToolSpec
	run  func(ctx context.Context, raw json.RawMessage) domain.ToolResult
	// runWithApproval is nil for tools that cannot accept one. The loop checks
	// for approval capability rather than assuming every tool has it.
	runWithApproval func(ctx context.Context, raw json.RawMessage, approvalID string, timeout time.Duration) domain.ToolResult
}

func (t toolAdapter) Spec() agent.ToolSpecView {
	return agent.ToolSpecView{
		Name:        t.spec.Name,
		Description: t.spec.Description,
		Parameters:  t.spec.Parameters,
		Risk:        t.spec.Risk,
	}
}

func (t toolAdapter) Invoke(ctx context.Context, raw json.RawMessage) domain.ToolResult {
	return t.run(ctx, raw)
}

// InvokeWithApproval forwards the one-shot approval to the tool that knows how
// to bind it. Without this the resumed run hits the same approval wall again.
func (t toolAdapter) InvokeWithApproval(ctx context.Context, raw json.RawMessage, approvalID string, timeout time.Duration) domain.ToolResult {
	if t.runWithApproval == nil {
		return t.run(ctx, raw)
	}
	return t.runWithApproval(ctx, raw, approvalID, timeout)
}

// agentTools converts the combined catalog into the loop's map.
func agentTools(runner *exec.Runner) (map[string]agent.Tool, []agent.SpecCatalogEntry) {
	tools := map[string]agent.Tool{}
	entries := make([]agent.SpecCatalogEntry, 0, 8)
	for _, tool := range exec.Tools(runner) {
		spec := tool.Spec()
		adapter := toolAdapter{name: spec.Name, spec: spec, run: tool.Invoke}
		// Both built-in and binary tools accept an approval; the type switch is
		// what lets the loop reach it without widening the generic interface.
		switch typed := tool.(type) {
		case *exec.WebTool:
			adapter.runWithApproval = typed.InvokeWithApproval
		case *exec.ScanTool:
			adapter.runWithApproval = typed.InvokeWithApproval
		}
		tools[spec.Name] = adapter
		entries = append(entries, agent.SpecCatalogEntry{Name: spec.Name, Risk: spec.Risk})
	}
	return tools, entries
}

// agentToolDocs renders the whitelist for the prompt, so the model sees exactly
// the tools whose calls the runner will accept.
func agentToolDocs(tools map[string]agent.Tool, whitelist []string) []agent.ToolDoc {
	docs := make([]agent.ToolDoc, 0, len(whitelist))
	for _, name := range whitelist {
		tool, ok := tools[name]
		if !ok {
			continue
		}
		spec := tool.Spec()
		docs = append(docs, agent.ToolDoc{Name: spec.Name, Risk: spec.Risk, Note: spec.Description})
	}
	return docs
}
