package agent

import (
	"context"
	"encoding/json"
	"testing"

	"soc/agent/internal/domain"
	"soc/agent/internal/llm"
)

// stubTool is a tool with a scripted result, so a loop test can drive the
// parking, stall and budget branches without a network or a real scanner.
type stubTool struct {
	name   string
	result domain.ToolResult
	// onInvoke runs before the result is returned, letting a test observe how
	// many times the loop actually executed the tool.
	onInvoke func()
}

func (s *stubTool) Spec() ToolSpecView {
	return ToolSpecView{
		Name:        s.name,
		Description: "stub",
		Parameters:  json.RawMessage(`{"type":"object"}`),
		Risk:        domain.RiskLight,
	}
}

func (s *stubTool) Invoke(context.Context, json.RawMessage) domain.ToolResult {
	if s.onInvoke != nil {
		s.onInvoke()
	}
	return s.result
}

func toolCall(id, name, args string) domain.CompletionResponse {
	return domain.CompletionResponse{
		ToolCalls: []domain.ToolCall{{ID: id, Name: name, Arguments: json.RawMessage(args)}},
		Usage:     domain.Usage{InputTokens: 10, OutputTokens: 5},
	}
}

func finalAnswer(text string) domain.CompletionResponse {
	return domain.CompletionResponse{
		Content: text,
		Usage:   domain.Usage{InputTokens: 10, OutputTokens: 5},
	}
}

func newLoop(spec AgentSpec, tools map[string]Tool) *Loop {
	return &Loop{
		Spec:   spec,
		Tools:  tools,
		System: "system",
	}
}

// withFake attaches a scripted model and returns the loop for chaining.
func (l *Loop) withFake(fake *llm.Fake) *Loop {
	l.LLM = fake
	l.Model = fake.Model()
	return l
}

func TestLoopStopsOnVerdict(t *testing.T) {
	fake := llm.NewFake("fake")
	fake.Queue(finalAnswer("done: nothing found"))

	result, err := newLoop(AgentSpec{MaxSteps: 5, MaxTokens: 1000}, map[string]Tool{}).
		withFake(fake).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Stop != StopVerdict {
		t.Fatalf("stop = %s, want verdict", result.Stop)
	}
	if result.Content != "done: nothing found" {
		t.Fatalf("content = %q", result.Content)
	}
}

func TestLoopParksOnApprovalInsteadOfRetrying(t *testing.T) {
	// This is the single most important property of the loop: an approval wall
	// must stop the run, not become a retry target. A model that retries it
	// spends the whole budget producing identical audit rows.
	calls := 0
	tool := &stubTool{
		name: "http_request",
		result: domain.ToolResult{
			OK:   false,
			Code: domain.CodeApprovalRequired,
			Details: map[string]string{
				"approval_argv": `["http_request","POST","https://t/x"]`,
				"target":        "t:443",
				"risk":          "active",
			},
		},
		onInvoke: func() { calls++ },
	}

	fake := llm.NewFake("fake")
	// Queue several identical calls: without parking, the loop would consume
	// all of them.
	for i := 0; i < 4; i++ {
		fake.Queue(toolCall("c1", "http_request", `{"url":"https://t/x"}`))
	}

	result, err := newLoop(
		AgentSpec{MaxSteps: 10, MaxTokens: 10000},
		map[string]Tool{"http_request": tool},
	).withFake(fake).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Stop != StopApproval {
		t.Fatalf("stop = %s, want approval", result.Stop)
	}
	if calls != 1 {
		t.Fatalf("tool executed %d times, want exactly 1 (no retry after parking)", calls)
	}
	if result.Pending == nil {
		t.Fatal("Pending is nil, so the caller cannot request an approval")
	}
	if result.Pending.Target != "t:443" || result.Pending.Risk != "active" {
		t.Fatalf("pending = %+v", result.Pending)
	}
	// The binding must survive, otherwise the approval can never match.
	if len(result.Pending.Argv) != 3 || result.Pending.Argv[1] != "POST" {
		t.Fatalf("pending argv = %v", result.Pending.Argv)
	}
}

func TestLoopDetectsStallOnIdenticalCalls(t *testing.T) {
	calls := 0
	tool := &stubTool{
		name:   "web_fetch",
		result: domain.ToolResult{OK: false, Code: domain.CodeTimeout},
		onInvoke: func() {
			calls++
		},
	}
	fake := llm.NewFake("fake")
	for i := 0; i < 6; i++ {
		fake.Queue(toolCall("c1", "web_fetch", `{"host":"t"}`))
	}

	result, err := newLoop(
		AgentSpec{MaxSteps: 10, MaxTokens: 100000},
		map[string]Tool{"web_fetch": tool},
	).withFake(fake).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Stop != StopStall {
		t.Fatalf("stop = %s, want stall", result.Stop)
	}
	// maxIdenticalCalls is 2, so the tool runs twice and the third attempt is
	// refused rather than executed again.
	if calls != maxIdenticalCalls {
		t.Fatalf("tool executed %d times, want %d", calls, maxIdenticalCalls)
	}
}

func TestLoopDoesNotTreatDifferentArgumentsAsStall(t *testing.T) {
	calls := 0
	tool := &stubTool{
		name:     "web_fetch",
		result:   domain.ToolResult{OK: true, Code: "ok"},
		onInvoke: func() { calls++ },
	}
	fake := llm.NewFake("fake")
	fake.Queue(toolCall("c1", "web_fetch", `{"path":"/a"}`))
	fake.Queue(toolCall("c2", "web_fetch", `{"path": "/b"}`))
	fake.Queue(toolCall("c3", "web_fetch", `{ "path" : "/b" }`)) // same as c2, different spacing
	fake.Queue(finalAnswer("done"))

	result, err := newLoop(
		AgentSpec{MaxSteps: 10, MaxTokens: 100000},
		map[string]Tool{"web_fetch": tool},
	).withFake(fake).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Stop != StopVerdict {
		t.Fatalf("stop = %s, want verdict; distinct arguments must not look stuck", result.Stop)
	}
	if calls != 3 {
		t.Fatalf("tool executed %d times, want 3", calls)
	}
}

func TestLoopStopsOnStepBudget(t *testing.T) {
	tool := &stubTool{
		name:   "web_fetch",
		result: domain.ToolResult{OK: true, Code: "ok"},
	}
	fake := llm.NewFake("fake")
	for i := 0; i < 10; i++ {
		// Distinct arguments so the stall detector does not fire first.
		fake.Queue(toolCall("c1", "web_fetch", `{"path":"/`+string(rune('a'+i))+`"}`))
	}

	result, err := newLoop(
		AgentSpec{MaxSteps: 3, MaxTokens: 100000},
		map[string]Tool{"web_fetch": tool},
	).withFake(fake).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Stop != StopBudget {
		t.Fatalf("stop = %s, want budget", result.Stop)
	}
	// Budget is a designed stop, not an error: the caller may resume.
	if result.Stop == StopFatal {
		t.Fatal("a step budget must not be reported as fatal")
	}
}

func TestLoopStopsOnTokenBudget(t *testing.T) {
	tool := &stubTool{name: "web_fetch", result: domain.ToolResult{OK: true, Code: "ok"}}
	fake := llm.NewFake("fake")
	for i := 0; i < 10; i++ {
		fake.Queue(toolCall("c1", "web_fetch", `{"path":"/`+string(rune('a'+i))+`"}`))
	}

	result, err := newLoop(
		AgentSpec{MaxSteps: 100, MaxTokens: 20},
		map[string]Tool{"web_fetch": tool},
	).withFake(fake).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Stop != StopBudget {
		t.Fatalf("stop = %s, want budget", result.Stop)
	}
	if result.ToolCalls > 2 {
		t.Fatalf("tool calls = %d; the token cap should stop the run almost immediately", result.ToolCalls)
	}
}

func TestLoopReportsUnknownToolWithoutExecutingIt(t *testing.T) {
	fake := llm.NewFake("fake")
	fake.Queue(toolCall("c1", "sqlmap_invented", `{}`))
	fake.Queue(toolCall("c2", "sqlmap_invented", `{}`))
	fake.Queue(finalAnswer("giving up"))

	result, err := newLoop(
		AgentSpec{MaxSteps: 5, MaxTokens: 10000},
		map[string]Tool{"web_fetch": &stubTool{name: "web_fetch"}},
	).withFake(fake).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.ToolCalls != 0 {
		t.Fatalf("tool calls = %d, want 0: an unknown tool must never be executed", result.ToolCalls)
	}
	if len(result.Steps) == 0 || result.Steps[0].Code != string(domain.CodeToolNotFound) {
		t.Fatalf("steps = %+v", result.Steps)
	}
}

func TestLoopStopsWhenModelRepeatedlyInventsTools(t *testing.T) {
	fake := llm.NewFake("fake")
	for i := 0; i < 5; i++ {
		fake.Queue(toolCall("c1", "sqlmap_invented", `{}`))
	}

	result, err := newLoop(
		AgentSpec{MaxSteps: 10, MaxTokens: 10000},
		map[string]Tool{},
	).withFake(fake).Run(context.Background())
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if result.Stop != StopFatal {
		t.Fatalf("stop = %s, want fatal: a model stuck on a nonexistent tool cannot be helped by retrying", result.Stop)
	}
}

func TestLoopReturnsModelError(t *testing.T) {
	fake := llm.NewFake("fake")
	fake.QueueError(context.DeadlineExceeded)

	result, err := newLoop(AgentSpec{MaxSteps: 5, MaxTokens: 1000}, map[string]Tool{}).
		withFake(fake).Run(context.Background())
	if err == nil {
		t.Fatal("a transport failure must be returned to the caller")
	}
	if result.Stop != StopFatal {
		t.Fatalf("stop = %s, want fatal", result.Stop)
	}
}

func TestLoopKeepsAssistantTurnWithToolCalls(t *testing.T) {
	// Providers reject a tool result whose originating call is missing from
	// history, so the assistant turn must be preserved verbatim.
	tool := &stubTool{name: "web_fetch", result: domain.ToolResult{OK: true, Code: "ok"}}
	fake := llm.NewFake("fake")
	fake.Queue(toolCall("call-1", "web_fetch", `{"path":"/a"}`))
	fake.Queue(finalAnswer("done"))

	if _, err := newLoop(
		AgentSpec{MaxSteps: 5, MaxTokens: 10000},
		map[string]Tool{"web_fetch": tool},
	).withFake(fake).Run(context.Background()); err != nil {
		t.Fatalf("Run returned error: %v", err)
	}

	requests := fake.Requests()
	if len(requests) < 2 {
		t.Fatalf("model requests = %d", len(requests))
	}
	second := requests[1].Messages
	foundAssistant, foundTool := false, false
	for _, message := range second {
		if message.Role == "assistant" && len(message.ToolCalls) == 1 && message.ToolCalls[0].ID == "call-1" {
			foundAssistant = true
		}
		if message.Role == "tool" && message.ToolCallID == "call-1" {
			foundTool = true
		}
	}
	if !foundAssistant {
		t.Fatal("the assistant turn with its tool call was not sent back to the model")
	}
	if !foundTool {
		t.Fatal("the tool result was not linked to its call id")
	}
}

func TestToolDefsOnlyIncludeWhitelist(t *testing.T) {
	tools := map[string]Tool{
		"web_fetch":    &stubTool{name: "web_fetch"},
		"http_request": &stubTool{name: "http_request"},
		"port_scan":    &stubTool{name: "port_scan"},
	}
	loop := newLoop(AgentSpec{Tools: []string{"web_fetch", "http_request"}}, tools)
	defs := loop.toolDefs()
	if len(defs) != 2 {
		t.Fatalf("tool defs = %d, want 2", len(defs))
	}
	for _, def := range defs {
		if def.Name == "port_scan" {
			t.Fatal("a tool outside the whitelist was exposed to the model")
		}
	}
}

func TestToolDefsEmptyWhenNoTools(t *testing.T) {
	loop := newLoop(AgentSpec{}, map[string]Tool{"web_fetch": &stubTool{name: "web_fetch"}})
	if defs := loop.toolDefs(); len(defs) != 0 {
		t.Fatalf("tool defs = %d, want 0 for a duty with no tools", len(defs))
	}
}
