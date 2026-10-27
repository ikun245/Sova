package domain

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestToolErrorIsMatchesSentinels(t *testing.T) {
	// Go callers keep using errors.Is, but the model receives a code. Both
	// views must stay consistent.
	cases := []struct {
		err      error
		sentinel error
	}{
		{NewToolError(CodePolicyDenied, "m", ""), ErrDenied},
		{NewToolError(CodeOutOfScope, "m", ""), ErrDenied},
		{NewToolError(CodeScopeExpired, "m", ""), ErrDenied},
		{NewToolError(CodeApprovalRequired, "m", ""), ErrNeedsApproval},
	}
	for _, tc := range cases {
		if !errors.Is(tc.err, tc.sentinel) {
			t.Fatalf("%v should match sentinel %v", tc.err, tc.sentinel)
		}
	}
}

func TestToolErrorDoesNotMatchWrongSentinel(t *testing.T) {
	err := NewToolError(CodePolicyDenied, "m", "")
	if errors.Is(err, ErrNeedsApproval) {
		t.Fatal("a denial must not look like an approval request")
	}
	approval := NewToolError(CodeApprovalRequired, "m", "")
	if errors.Is(approval, ErrDenied) {
		t.Fatal("an approval request must not look like a denial")
	}
}

func TestOnlyTransientCodesAreRetryable(t *testing.T) {
	retryable := []ErrorCode{CodeApprovalRequired, CodeTimeout, CodeInternal}
	for _, code := range retryable {
		if !code.Retryable() {
			t.Fatalf("%q should be retryable", code)
		}
	}
	terminal := []ErrorCode{
		CodeInvalidArgument, CodeToolNotFound, CodePolicyDenied, CodeOutOfScope,
		CodeScopeExpired, CodeApprovalRejected, CodeBinaryMissing, CodeCommandFailed,
		CodeBudgetExceeded, CodeInvalidOutput,
	}
	for _, code := range terminal {
		if code.Retryable() {
			t.Fatalf("%q must not be retryable; retrying would repeat a guaranteed failure", code)
		}
	}
}

func TestFailureEnvelopeCarriesCodeAndHint(t *testing.T) {
	err := NewToolError(CodeOutOfScope, "target is not authorized", "choose a target inside scope").
		WithDetail("target", "evil.test")

	envelope := Failure(err)
	if envelope.OK {
		t.Fatal("a failure envelope must not report ok")
	}
	if envelope.Code != CodeOutOfScope {
		t.Fatalf("Code = %q", envelope.Code)
	}
	if envelope.Hint == "" {
		t.Fatal("the envelope must carry an actionable hint, not just a message")
	}
	if envelope.Retryable {
		t.Fatal("out_of_scope is terminal; marking it retryable invites a loop")
	}
	if envelope.Details["target"] != "evil.test" {
		t.Fatalf("Details = %v, want the target preserved", envelope.Details)
	}
}

func TestEnvelopeIsValidJSONWithStableFields(t *testing.T) {
	envelope := Success("ok", map[string]string{"stdout": "x"}).
		WithMeta(&ResultMeta{Tool: "http_probe", Risk: "light", Target: "example.com:443"})

	var decoded map[string]any
	if err := json.Unmarshal([]byte(envelope.JSON()), &decoded); err != nil {
		t.Fatalf("envelope is not valid JSON: %v", err)
	}
	for _, field := range []string{"ok", "code", "retryable", "data", "meta"} {
		if _, ok := decoded[field]; !ok {
			t.Fatalf("envelope is missing the stable field %q", field)
		}
	}
	// Absent optional fields must be omitted, not rendered as misleading zero
	// values the model could mistake for a real answer.
	raw := envelope.JSON()
	if strings.Contains(raw, `"message":""`) || strings.Contains(raw, `"hint":""`) {
		t.Fatalf("empty optional fields should be omitted: %s", raw)
	}
}

func TestUncodedErrorBecomesInternalCode(t *testing.T) {
	// A tool that forgets to code its error must still produce a valid
	// envelope rather than leaking a bare string.
	envelope := Failure(errors.New("some raw failure"))
	if envelope.Code != CodeInternal {
		t.Fatalf("Code = %q, want %q", envelope.Code, CodeInternal)
	}
	if envelope.Message == "" {
		t.Fatal("the original message must be preserved")
	}
	if !envelope.Retryable {
		t.Fatal("internal errors are retryable by definition")
	}
}

func TestToolErrorDetailsAreCopiedNotShared(t *testing.T) {
	base := NewToolError(CodeOutOfScope, "m", "h").WithDetail("target", "a")
	derived := base.WithDetail("target", "b")

	if base.Details["target"] != "a" {
		t.Fatalf("WithDetail mutated the original: %v", base.Details)
	}
	if derived.Details["target"] != "b" {
		t.Fatalf("derived details = %v", derived.Details)
	}
}
