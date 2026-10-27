package exec

import (
	"context"
	"encoding/json"
	"testing"

	"soc/agent/internal/domain"
)

func TestInvokeReturnsEnvelopeForOutOfScope(t *testing.T) {
	runner := newTestRunner(t, nil)
	tool := NewScanTool("port_scan", "desc", []string{"nmap", "-sT", "{host}"}, domain.RiskActive, runner)

	result := tool.Invoke(context.Background(), json.RawMessage(`{"host":"evil.test","port":443}`))

	if result.OK {
		t.Fatal("an out-of-scope target must not report success")
	}
	if result.Code != domain.CodeOutOfScope {
		t.Fatalf("Code = %q, want %q", result.Code, domain.CodeOutOfScope)
	}
	if result.Hint == "" {
		t.Fatal("the model needs a hint to choose a different target")
	}
	if result.Retryable {
		t.Fatal("out_of_scope is terminal")
	}
	if result.Meta == nil || result.Meta.Tool != "port_scan" {
		t.Fatalf("Meta = %+v, want the tool name for attribution", result.Meta)
	}
	if result.Meta.Risk != string(domain.RiskActive) {
		t.Fatalf("Meta.Risk = %q, want the tool's declared risk", result.Meta.Risk)
	}
}

func TestInvokeReturnsEnvelopeForApprovalRequired(t *testing.T) {
	runner := newTestRunner(t, nil)
	runner.Lookup = staticLookup("203.0.113.10")
	tool := NewScanTool("port_scan", "desc", []string{"nmap", "-sT", "{host}"}, domain.RiskActive, runner)

	result := tool.Invoke(context.Background(), json.RawMessage(`{"host":"example.com","port":443}`))

	if result.Code != domain.CodeApprovalRequired {
		t.Fatalf("Code = %q, want %q", result.Code, domain.CodeApprovalRequired)
	}
	if !result.Retryable {
		t.Fatal("approval_required is retryable once a human approves")
	}
}

func TestInvokeReturnsInvalidArgumentForBadInput(t *testing.T) {
	runner := newTestRunner(t, nil)
	tool := NewScanTool("dns_lookup", "desc", []string{"dig", "{host}"}, domain.RiskPassive, runner)

	result := tool.Invoke(context.Background(), json.RawMessage(`{"nope":1}`))
	if result.Code != domain.CodeInvalidArgument {
		t.Fatalf("Code = %q, want %q", result.Code, domain.CodeInvalidArgument)
	}
	if result.Retryable {
		t.Fatal("invalid arguments must be fixed, not retried unchanged")
	}
}

func TestCallReturnsJSONEvenOnFailure(t *testing.T) {
	runner := newTestRunner(t, nil)
	tool := NewScanTool("port_scan", "desc", []string{"nmap", "{host}"}, domain.RiskActive, runner)

	payload, err := tool.Call(context.Background(), json.RawMessage(`{"host":"evil.test"}`))
	if err == nil {
		t.Fatal("Call() should also return the coded error for Go callers")
	}
	// The string payload must still be parseable: a harness that only forwards
	// the text must not lose the code.
	var decoded domain.ToolResult
	if jsonErr := json.Unmarshal([]byte(payload), &decoded); jsonErr != nil {
		t.Fatalf("Call() returned non-JSON: %v", jsonErr)
	}
	if decoded.Code != domain.CodeOutOfScope {
		t.Fatalf("decoded code = %q, want %q", decoded.Code, domain.CodeOutOfScope)
	}
	toolErr := domain.AsToolError(err)
	if toolErr.Code != decoded.Code {
		t.Fatal("the error code and the envelope code must agree, or callers see two truths")
	}
}
