package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"soc/agent/internal/domain"
)

// StopReason is why a loop ended. Every run records exactly one, so an operator
// can tell "finished" from "ran out of money" from "waiting for a human".
type StopReason string

const (
	// StopVerdict means the model produced a final answer.
	StopVerdict StopReason = "verdict"
	// StopBudget means a step or token cap was reached. Not an error: it is a
	// designed stop, so the caller may grant a larger budget and resume.
	StopBudget StopReason = "budget"
	// StopStall means no progress was detected. Continuing would repeat the
	// same failing call and spend the budget for nothing.
	StopStall StopReason = "stall"
	// StopApproval means a human must approve an exact action. The loop parks
	// instead of retrying, because a model that retries an approval wall will
	// do it until the budget is gone.
	StopApproval StopReason = "approval"
	// StopFatal means the run cannot continue: unknown tool, revoked scope,
	// malformed model output after a retry.
	StopFatal StopReason = "fatal"
)

// PendingApproval is the parked work item. It carries the exact binding a human
// must authorize, so the caller can turn it into a scope_approvals row without
// guessing a body digest.
type PendingApproval struct {
	Tool      string          `json:"tool"`
	Argv      []string        `json:"argv"`
	Target    string          `json:"target"`
	Risk      string          `json:"risk"`
	Arguments json.RawMessage `json:"arguments"`
}

// Step is one observed iteration, kept so a caller can show the trail instead
// of asking the user to trust a summary.
type Step struct {
	Index  int
	Kind   string
	Tool   string
	Args   string
	Code   string
	Detail string
	Tokens int
}

// RunResult is the outcome of one agent run.
type RunResult struct {
	Stop      StopReason
	Message   string
	Content   string
	Steps     []Step
	ToolCalls int
	Tokens    int
	Pending   *PendingApproval
	Messages  []domain.Message
	StartedAt time.Time
	Duration  time.Duration
}

// Tool is the narrow surface the loop needs. It matches exec.Tool, so the real
// catalog drops in without an adapter.
type Tool interface {
	Spec() ToolSpecView
	Invoke(ctx context.Context, raw json.RawMessage) domain.ToolResult
}

// ApprovalAware is implemented by tools that can bind a one-shot approval to
// one call. It is optional so a tool that does not support approvals does not
// have to pretend it does.
type ApprovalAware interface {
	InvokeWithApproval(ctx context.Context, raw json.RawMessage, approvalID string, timeout time.Duration) domain.ToolResult
}

// ToolSpecView is the model-facing tool description.
type ToolSpecView struct {
	Name        string
	Description string
	Parameters  json.RawMessage
	Risk        domain.RiskLevel
}

// Loop drives one duty until it stops for a recorded reason.
type Loop struct {
	LLM   domain.LLM
	Model string
	Spec  AgentSpec
	Tools map[string]Tool
	// System is the composed prompt. It is built by the caller from the same
	// scope values the executor enforces, so the prompt cannot promise more
	// than the code allows.
	System string
	// ApprovalID authorizes exactly one parked action on resume.
	ApprovalID string
	// ResumeMessages lets a caller continue a previous run.
	ResumeMessages []domain.Message
	// OnStep is optional progress reporting; a CLI uses it to stream.
	OnStep func(Step)
}

// maxIdenticalCalls is how many times the same tool with the same arguments may
// appear before the run is judged stuck. Two is enough: a model that repeats a
// failing call verbatim is not converging.
const maxIdenticalCalls = 2

// Run executes the loop.
func (l *Loop) Run(ctx context.Context) (RunResult, error) {
	started := time.Now()
	result := RunResult{StartedAt: started, Messages: l.ResumeMessages}

	messages := make([]domain.Message, 0, 16)
	messages = append(messages, domain.Message{Role: "system", Content: l.System})
	messages = append(messages, l.ResumeMessages...)

	toolDefs := l.toolDefs()
	seen := map[string]int{}
	tokens := 0

	for step := 1; step <= l.Spec.MaxSteps; step++ {
		if tokens >= l.Spec.MaxTokens {
			result.Stop = StopBudget
			result.Message = fmt.Sprintf("token budget exhausted (%d/%d)", tokens, l.Spec.MaxTokens)
			result.Tokens = tokens
			result.Messages = tail(messages)
			result.Duration = time.Since(started)
			return result, nil
		}

		resp, err := l.LLM.Complete(ctx, domain.CompletionRequest{
			Model:       l.Model,
			Messages:    messages,
			Tools:       toolDefs,
			Temperature: 0.2,
			MaxTokens:   2048,
		})
		if err != nil {
			result.Stop = StopFatal
			result.Message = "model call failed: " + err.Error()
			result.Tokens = tokens
			result.Messages = tail(messages)
			result.Duration = time.Since(started)
			return result, err
		}
		tokens += resp.Usage.InputTokens + resp.Usage.OutputTokens

		if len(resp.ToolCalls) == 0 {
			result.Stop = StopVerdict
			result.Content = strings.TrimSpace(resp.Content)
			result.Message = "model produced a final answer"
			result.Tokens = tokens
			messages = append(messages, domain.Message{Role: "assistant", Content: resp.Content})
			result.Messages = tail(messages)
			result.Duration = time.Since(started)
			return result, nil
		}

		// The assistant turn must be preserved verbatim: the tool results that
		// follow reference its call ids, and providers reject a result whose
		// call is missing from history.
		messages = append(messages, domain.Message{
			Role:      "assistant",
			Content:   resp.Content,
			ToolCalls: resp.ToolCalls,
		})

		for _, call := range resp.ToolCalls {
			fingerprint := call.Name + "|" + canonicalJSON(call.Arguments)
			seen[fingerprint]++
			if seen[fingerprint] > maxIdenticalCalls {
				result.Stop = StopStall
				result.Message = fmt.Sprintf("%s called %d times with identical arguments; no progress",
					call.Name, seen[fingerprint]-1)
				result.Tokens = tokens
				result.Messages = tail(messages)
				result.Duration = time.Since(started)
				return result, nil
			}

			tool, ok := l.Tools[call.Name]
			if !ok {
				// An unknown tool is a prompt/catalog mismatch, not something
				// the model can fix by trying again. Tell it once, then stop.
				if seen[fingerprint] > 1 {
					result.Stop = StopFatal
					result.Message = "model repeatedly requested a tool it does not have: " + call.Name
					result.Tokens = tokens
					result.Messages = tail(messages)
					result.Duration = time.Since(started)
					return result, nil
				}
				messages = append(messages, domain.Message{
					Role:       "tool",
					ToolCallID: call.ID,
					Name:       call.Name,
					Content:    `{"ok":false,"code":"tool_not_found","message":"this tool is not in your whitelist","hint":"use only the tools listed in the system prompt"}`,
				})
				result.Steps = append(result.Steps, Step{Index: step, Kind: "tool_error", Tool: call.Name, Code: "tool_not_found"})
				continue
			}

			envelope := l.invoke(ctx, tool, call)
			result.ToolCalls++

			// A spent or mismatched approval must not keep being attached. Once it
			// is used, every later ask-level call would report approval_consumed,
			// which reads as a broken approval rather than "ask a human for this
			// different action". Dropping it makes the next wall park cleanly with
			// its own binding.
			if envelope.Code == domain.CodeApprovalConsumed || envelope.Code == domain.CodeApprovalMismatch {
				l.ApprovalID = ""
			}

			// Parking: an approval request is not a failure the model should
			// work around. Record the exact binding and stop.
			if envelope.Code == domain.CodeApprovalRequired {
				binding := []string{}
				if raw, ok := envelope.Details["approval_argv"]; ok && raw != "" {
					_ = json.Unmarshal([]byte(raw), &binding)
				}
				result.Stop = StopApproval
				result.Pending = &PendingApproval{
					Tool:      call.Name,
					Argv:      binding,
					Target:    envelope.Details["target"],
					Risk:      envelope.Details["risk"],
					Arguments: call.Arguments,
				}
				result.Message = "a human must approve this exact action before it can run"
				result.Tokens = tokens
				result.Messages = tail(messages)
				result.Duration = time.Since(started)
				l.emit(Step{Index: step, Kind: "approval", Tool: call.Name, Code: string(envelope.Code), Detail: envelope.Message})
				return result, nil
			}

			payload := envelope.JSON()
			messages = append(messages, domain.Message{
				Role:       "tool",
				ToolCallID: call.ID,
				Name:       call.Name,
				Content:    payload,
			})
			l.emit(Step{Index: step, Kind: "tool", Tool: call.Name, Args: truncate(string(call.Arguments), 160),
				Code: string(envelope.Code), Detail: truncate(envelope.Message, 200)})
			result.Steps = append(result.Steps, Step{Index: step, Kind: "tool", Tool: call.Name,
				Args: truncate(string(call.Arguments), 160), Code: string(envelope.Code)})
		}
	}

	result.Stop = StopBudget
	result.Message = fmt.Sprintf("step budget exhausted (%d steps)", l.Spec.MaxSteps)
	result.Tokens = tokens
	result.Messages = tail(messages)
	result.Duration = time.Since(started)
	return result, nil
}

func (l *Loop) emit(step Step) {
	if l.OnStep != nil {
		l.OnStep(step)
	}
}

// invoke runs the tool, passing the resumed approval if one is present.
//
// The approval is handed to every call rather than consumed here, because the
// loop is the wrong place to decide whether an approval was used: it cannot tell
// a light tool (which ignores the id) from an active one that spends it. Clearing
// on the first call meant a light probe silently ate the approval and the active
// tool that needed it parked again — a livelock where each human approval bought
// nothing.
//
// Single use is enforced where it can be enforced correctly: the store's
// ConsumeApproval is one atomic UPDATE bound to scope+target+argv, so a second
// use fails with approval_consumed and a different action fails with
// approval_mismatch. The security property does not depend on this function.
func (l *Loop) invoke(ctx context.Context, tool Tool, call domain.ToolCall) domain.ToolResult {
	if l.ApprovalID == "" {
		return tool.Invoke(ctx, call.Arguments)
	}
	aware, ok := tool.(ApprovalAware)
	if !ok {
		return tool.Invoke(ctx, call.Arguments)
	}
	return aware.InvokeWithApproval(ctx, call.Arguments, l.ApprovalID, 0)
}

// toolDefs converts the whitelist into model-facing schemas. A tool the model
// can see is a tool the runner may refuse, but never one it cannot name.
func (l *Loop) toolDefs() []domain.ToolDef {
	if len(l.Spec.Tools) == 0 {
		return nil
	}
	defs := make([]domain.ToolDef, 0, len(l.Spec.Tools))
	for _, name := range l.Spec.Tools {
		tool, ok := l.Tools[name]
		if !ok {
			continue
		}
		spec := tool.Spec()
		defs = append(defs, domain.ToolDef{
			Name:        spec.Name,
			Description: spec.Description,
			Parameters:  spec.Parameters,
		})
	}
	return defs
}

// canonicalJSON normalises whitespace so two identical argument objects that
// differ only in spacing are recognised as the same call.
func canonicalJSON(raw json.RawMessage) string {
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return string(raw)
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return string(raw)
	}
	return string(encoded)
}

// tail keeps the most recent messages so a returned transcript stays small.
func tail(messages []domain.Message) []domain.Message {
	const keep = 20
	if len(messages) <= keep {
		return messages
	}
	return messages[len(messages)-keep:]
}

// truncate shortens a string for a log line without splitting a UTF-8 rune.
// Slicing bytes would corrupt Chinese arguments into invalid UTF-8, which then
// lands in the audit trail and makes a record unreadable.
func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	cut := limit
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return value[:cut] + "..."
}
