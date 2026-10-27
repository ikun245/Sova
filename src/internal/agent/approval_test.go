package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"soc/agent/internal/domain"
	"soc/agent/internal/llm"
)

// approvalTool fails with approval_required when called without an approval,
// which is what a real scoped tool does.
type approvalTool struct {
	name          string
	plainCalls    int
	approvedCalls int
	lastID        string
}

func (a *approvalTool) Spec() ToolSpecView {
	return ToolSpecView{Name: a.name, Parameters: json.RawMessage(`{"type":"object"}`), Risk: domain.RiskLight}
}

func (a *approvalTool) Invoke(context.Context, json.RawMessage) domain.ToolResult {
	a.plainCalls++
	return domain.ToolResult{
		OK:      false,
		Code:    domain.CodeApprovalRequired,
		Details: map[string]string{"approval_argv": `["` + a.name + `","POST"]`, "target": "t:443", "risk": "active"},
	}
}

func (a *approvalTool) InvokeWithApproval(_ context.Context, _ json.RawMessage, approvalID string, _ time.Duration) domain.ToolResult {
	a.approvedCalls++
	a.lastID = approvalID
	return domain.ToolResult{OK: true, Code: "ok"}
}

func TestLoopSpendsApprovalOnResume(t *testing.T) {
	// Regression: ApprovalID was stored on the loop but never reached the tool,
	// so a resumed run hit the same approval wall and reported stop=approval
	// again. The whole parking mechanism was decorative until this worked.
	tool := &approvalTool{name: "http_request"}
	fake := llm.NewFake("fake")
	fake.Queue(toolCall("c1", "http_request", `{"url":"https://t/x"}`))
	fake.Queue(finalAnswer("done"))

	loop := newLoop(AgentSpec{MaxSteps: 5, MaxTokens: 10000}, map[string]Tool{"http_request": tool}).withFake(fake)
	loop.ApprovalID = "approval-123"

	result, err := loop.Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Stop != StopVerdict {
		t.Fatalf("stop = %s, want verdict", result.Stop)
	}
	if tool.approvedCalls != 1 {
		t.Fatalf("InvokeWithApproval called %d times, want 1", tool.approvedCalls)
	}
	if tool.lastID != "approval-123" {
		t.Fatalf("approval id = %q, want approval-123", tool.lastID)
	}
	if tool.plainCalls != 0 {
		t.Fatalf("the unapproved path ran %d times; the approval must be used instead", tool.plainCalls)
	}
}

func TestLoopPassesTheApprovalToEveryCall(t *testing.T) {
	// Regression: the loop cleared the approval after the first tool call, even
	// when that call was a light probe that ignored it. The active tool that
	// actually needed it then parked again, so each human approval bought nothing
	// and the run livelocked between "approve" and "needs approval".
	//
	// Single use is the store's job (ConsumeApproval is one atomic UPDATE bound to
	// scope+target+argv), not the loop's.
	tool := &approvalTool{name: "http_request"}
	fake := llm.NewFake("fake")
	fake.Queue(toolCall("c1", "web_fetch", `{"host":"t"}`))
	fake.Queue(toolCall("c2", "http_request", `{"url":"https://t/x"}`))
	fake.Queue(finalAnswer("done"))

	loop := newLoop(AgentSpec{MaxSteps: 5, MaxTokens: 10000},
		map[string]Tool{
			// A light probe that ignores any approval, like http_probe does.
			"web_fetch":    &stubTool{name: "web_fetch", result: domain.ToolResult{OK: true, Code: "ok"}},
			"http_request": tool,
		}).withFake(fake)
	loop.ApprovalID = "approval-1"

	result, err := loop.Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if tool.approvedCalls != 1 {
		t.Fatalf("the active tool received the approval %d times, want 1", tool.approvedCalls)
	}
	if tool.lastID != "approval-1" {
		t.Fatalf("approval id = %q, want approval-1", tool.lastID)
	}
	if result.Stop != StopVerdict {
		t.Fatalf("stop = %s, want verdict after the approved call ran", result.Stop)
	}
}

func TestLoopDropsASpentApprovalSoTheNextWallParksCleanly(t *testing.T) {
	// A resumed approval is spent on the first action it authorized. Later
	// ask-level calls must park with their own binding, not report the spent id as
	// approval_consumed, which reads as a broken approval rather than "ask a human
	// about this different action".
	calls := 0
	tool := &stubTool{name: "http_request", result: domain.ToolResult{
		OK:   false,
		Code: domain.CodeApprovalConsumed,
		Details: map[string]string{
			"approval_argv": `["http_request","POST"]`,
			"target":        "t:443",
			"risk":          "active",
		},
	}}
	tool.onInvoke = func() { calls++ }

	fake := llm.NewFake("fake")
	fake.Queue(toolCall("c1", "http_request", `{"url":"https://t/a"}`))
	fake.Queue(toolCall("c2", "http_request", `{"url":"https://t/b"}`))
	fake.Queue(finalAnswer("done"))

	loop := newLoop(AgentSpec{MaxSteps: 5, MaxTokens: 10000},
		map[string]Tool{"http_request": tool}).withFake(fake)
	loop.ApprovalID = "approval-1"

	result, err := loop.Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if calls != 2 {
		t.Fatalf("tool ran %d times, want 2", calls)
	}
	// The second call ran without the spent approval, so it reported the wall the
	// stub actually returned rather than being skipped.
	if loop.ApprovalID != "" {
		t.Fatalf("the spent approval was kept: %q", loop.ApprovalID)
	}
	if result.Stop != StopVerdict {
		t.Fatalf("stop = %s", result.Stop)
	}
}

func TestLoopFallsBackForToolsWithoutApprovalSupport(t *testing.T) {
	// A tool that cannot accept an approval must not be handed one silently:
	// the loop calls it normally, and it is expected to park on its own.
	tool := &noApprovalTool{}
	fake := llm.NewFake("fake")
	fake.Queue(toolCall("c1", "web_fetch", `{"host":"t"}`))

	loop := newLoop(AgentSpec{MaxSteps: 3, MaxTokens: 10000}, map[string]Tool{"web_fetch": tool}).withFake(fake)
	loop.ApprovalID = "approval-1"

	result, err := loop.Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if tool.calls != 1 {
		t.Fatalf("Invoke called %d times, want 1", tool.calls)
	}
	if result.Stop != StopApproval {
		t.Fatalf("stop = %s, want approval", result.Stop)
	}
}

type noApprovalTool struct{ calls int }

func (n *noApprovalTool) Spec() ToolSpecView {
	return ToolSpecView{Name: "web_fetch", Parameters: json.RawMessage(`{"type":"object"}`), Risk: domain.RiskLight}
}

func (n *noApprovalTool) Invoke(context.Context, json.RawMessage) domain.ToolResult {
	n.calls++
	return domain.ToolResult{
		OK:      false,
		Code:    domain.CodeApprovalRequired,
		Details: map[string]string{"target": "t:443", "risk": "active"},
	}
}
