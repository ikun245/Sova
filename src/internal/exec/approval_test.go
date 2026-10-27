package exec

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"soc/agent/internal/domain"
)

// approvalStub stands in for the real store so the runner's contract can be
// tested without a database.
type approvalStub struct {
	accept   bool
	err      error
	consumed []domain.ApprovalCheck
}

func (s *approvalStub) ConsumeApproval(_ context.Context, check domain.ApprovalCheck) (domain.Approval, error) {
	s.consumed = append(s.consumed, check)
	if s.err != nil {
		return domain.Approval{}, s.err
	}
	if !s.accept {
		return domain.Approval{}, domain.NewToolError(domain.CodeApprovalMismatch,
			"approval does not match this command", "request approval for this exact command")
	}
	return domain.Approval{ID: check.ApprovalID, Decision: domain.ApprovalApproved, DecidedBy: "analyst"}, nil
}

func activeRunner(t *testing.T, approvals domain.ApprovalVerifier) *Runner {
	t.Helper()
	runner := NewRunner(
		Policy{Ceiling: domain.RiskActive, AskAbove: domain.RiskLight},
		testScope(), &recordingAudit{},
	)
	runner.Lookup = staticLookup("203.0.113.10")
	runner.LookPath = func(program string) (string, error) { return "/usr/bin/" + program, nil }
	runner.Approvals = approvals
	return runner
}

func TestNonEmptyApprovalIDIsNotEnough(t *testing.T) {
	// The whole point of the gate: an arbitrary string must not authorize an
	// active command.
	runner := activeRunner(t, &approvalStub{accept: false})

	_, err := runner.Execute(context.Background(), Request{
		Argv:       []string{"nmap", "-sV", "example.com"},
		Target:     domain.Target{Host: "example.com", Port: 443},
		ApprovalID: "made-up-id",
	})
	if err == nil {
		t.Fatal("a fabricated approval id must not authorize an active command")
	}
	if domain.AsToolError(err).Code != domain.CodeApprovalMismatch {
		t.Fatalf("code = %q, want %q", domain.AsToolError(err).Code, domain.CodeApprovalMismatch)
	}
}

func TestMissingVerifierFailsClosed(t *testing.T) {
	runner := activeRunner(t, nil)

	_, err := runner.Execute(context.Background(), Request{
		Argv:       []string{"nmap", "-sV", "example.com"},
		Target:     domain.Target{Host: "example.com", Port: 443},
		ApprovalID: "some-id",
	})
	toolErr := domain.AsToolError(err)
	if toolErr.Code != domain.CodeApprovalRequired {
		t.Fatalf("code = %q, want approval_required", toolErr.Code)
	}
	if toolErr.Hint == "" {
		t.Fatal("the operator needs to know verification is unconfigured")
	}
}

func TestVerifierReceivesExactBinding(t *testing.T) {
	// Exercised directly so the assertion does not depend on which scanners
	// happen to be installed on the test machine.
	stub := &approvalStub{accept: true}
	runner := activeRunner(t, stub)

	target := domain.Target{Host: "example.com", Port: 443}
	argv := []string{"nmap", "-sV", "example.com"}
	entry := AuditEntry{}
	if err := runner.consumeApproval(context.Background(), Request{
		Argv: argv, Target: target, ApprovalID: "ap-1",
	}, Classification{Risk: domain.RiskActive, Decision: DecisionAsk}, &entry); err != nil {
		t.Fatalf("consumeApproval() error = %v", err)
	}

	if len(stub.consumed) != 1 {
		t.Fatalf("verifier calls = %d, want 1", len(stub.consumed))
	}
	check := stub.consumed[0]
	if check.ApprovalID != "ap-1" {
		t.Fatalf("ApprovalID = %q", check.ApprovalID)
	}
	if check.ScopeID != testScope().ID {
		t.Fatalf("ScopeID = %q, want the runner's scope", check.ScopeID)
	}
	if check.Target != target.String() {
		t.Fatalf("Target = %q, want %q", check.Target, target.String())
	}
	if string(check.Argv) != `["nmap","-sV","example.com"]` {
		t.Fatalf("Argv = %s, want the normalized exact command", check.Argv)
	}
	if entry.ApprovalID != "ap-1" {
		t.Fatalf("the audit entry must record which approval authorized the call: %+v", entry)
	}
}

func TestArgvOrderIsPartOfTheApproval(t *testing.T) {
	// Two argument orders are two different commands; a human approved one.
	stub := &approvalStub{accept: true}
	runner := activeRunner(t, stub)
	entry := AuditEntry{}

	_ = runner.consumeApproval(context.Background(), Request{
		Argv:       []string{"nmap", "example.com", "-sV"},
		Target:     domain.Target{Host: "example.com", Port: 443},
		ApprovalID: "ap-2",
	}, Classification{Risk: domain.RiskActive, Decision: DecisionAsk}, &entry)

	got := string(stub.consumed[0].Argv)
	if got == `["nmap","-sV","example.com"]` {
		t.Fatal("normalization must preserve argument order, otherwise a reordered command reuses the approval")
	}
}

func TestMissingBinaryDoesNotSpendTheApproval(t *testing.T) {
	// Burning a human approval on a command that cannot run would force a
	// pointless re-approval, so availability is checked first.
	stub := &approvalStub{accept: true}
	runner := activeRunner(t, stub)
	runner.LookPath = func(string) (string, error) { return "", errors.New("not found") }

	_, err := runner.Execute(context.Background(), Request{
		Argv:       []string{"nmap", "-sV", "example.com"},
		Target:     domain.Target{Host: "example.com", Port: 443},
		ApprovalID: "ap-5",
	})
	if err == nil {
		t.Fatal("expected the missing binary to be reported")
	}
	if domain.AsToolError(err).Code != domain.CodeBinaryMissing {
		t.Fatalf("code = %q, want binary_missing", domain.AsToolError(err).Code)
	}
	if len(stub.consumed) != 0 {
		t.Fatal("an approval must not be consumed when the command cannot even start")
	}
}

func TestApprovalCannotOverridePolicyDeny(t *testing.T) {
	// A monotonic guard: an approval authorizes a permitted-but-risky command,
	// never one the policy forbids outright.
	stub := &approvalStub{accept: true}
	runner := activeRunner(t, stub)

	_, err := runner.Execute(context.Background(), Request{
		Argv:       []string{"rm", "-rf", "/"},
		Target:     domain.Target{Host: "example.com"},
		ApprovalID: "ap-evil",
	})
	if domain.AsToolError(err).Code != domain.CodePolicyDenied {
		t.Fatalf("code = %q, want policy_denied", domain.AsToolError(err).Code)
	}
	if len(stub.consumed) != 0 {
		t.Fatal("a denied command must not even consult the approval store")
	}
}

func TestApprovalCannotOverrideScope(t *testing.T) {
	// Scope is checked before approval, so a human is never asked to bless an
	// out-of-scope target and an approval can never widen the engagement.
	stub := &approvalStub{accept: true}
	runner := activeRunner(t, stub)

	_, err := runner.Execute(context.Background(), Request{
		Argv:       []string{"nmap", "-sV", "evil.test"},
		Target:     domain.Target{Host: "evil.test", Port: 443},
		ApprovalID: "ap-3",
	})
	if domain.AsToolError(err).Code != domain.CodeOutOfScope {
		t.Fatalf("code = %q, want out_of_scope", domain.AsToolError(err).Code)
	}
	if len(stub.consumed) != 0 {
		t.Fatal("an out-of-scope target must not reach the approval store")
	}
}

func TestConsumedApprovalSurfacesAsConsumed(t *testing.T) {
	runner := activeRunner(t, &approvalStub{err: domain.NewToolError(
		domain.CodeApprovalConsumed, "already used", "request a new approval")})

	_, err := runner.Execute(context.Background(), Request{
		Argv:       []string{"nmap", "-sV", "example.com"},
		Target:     domain.Target{Host: "example.com", Port: 443},
		ApprovalID: "ap-used",
	})
	if domain.AsToolError(err).Code != domain.CodeApprovalConsumed {
		t.Fatalf("code = %q, want approval_consumed", domain.AsToolError(err).Code)
	}
}

func TestApprovedCallRecordsDecisionInAudit(t *testing.T) {
	audit := &recordingAudit{}
	stub := &approvalStub{accept: true}
	runner := NewRunner(
		Policy{Ceiling: domain.RiskActive, AskAbove: domain.RiskLight},
		testScope(), audit,
	)
	runner.Lookup = staticLookup("203.0.113.10")
	runner.LookPath = func(program string) (string, error) { return "/usr/bin/" + program, nil }
	runner.Approvals = stub

	_, _ = runner.Execute(context.Background(), Request{
		Argv:       []string{"nmap", "-sV", "example.com"},
		Target:     domain.Target{Host: "example.com", Port: 443},
		ApprovalID: "ap-4",
	})

	if len(audit.entries) != 1 {
		t.Fatalf("audit entries = %d", len(audit.entries))
	}
	entry := audit.entries[0]
	if entry.ApprovalID != "ap-4" {
		t.Fatalf("ApprovalID not recorded: %+v", entry)
	}
	if entry.Decision != DecisionAsk {
		t.Fatalf("Decision = %q, want ask (the call needed approval)", entry.Decision)
	}
}

func TestNormalizeArgvIsStable(t *testing.T) {
	first := domain.NormalizeArgv([]string{"a", "b"})
	second := domain.NormalizeArgv([]string{"a", "b"})
	if string(first) != string(second) {
		t.Fatal("the same argv must normalize identically, or approvals never match")
	}
	var decoded []string
	if err := json.Unmarshal(first, &decoded); err != nil {
		t.Fatalf("normalized argv is not JSON: %v", err)
	}
	if errors.Is(errors.New("x"), errors.New("y")) {
		t.Fatal("unreachable")
	}
}
