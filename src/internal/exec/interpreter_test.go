package exec

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"soc/agent/internal/domain"
	"soc/agent/internal/sandbox"
)

func interpreterRunner(t *testing.T, gate *SandboxGate) *Runner {
	t.Helper()
	runner := NewRunner(
		Policy{Ceiling: domain.RiskCodeExecution, AskAbove: domain.RiskActive, Interpreter: true},
		testScope(), &recordingAudit{},
	)
	runner.Lookup = staticLookup("203.0.113.10")
	runner.LookPath = func(program string) (string, error) { return "/usr/bin/" + program, nil }
	runner.Approvals = &approvalStub{accept: true}
	runner.Sandbox = gate
	return runner
}

func confinedGate() *SandboxGate {
	return &SandboxGate{
		Policy: sandbox.Policy{
			Mode:          sandbox.ModeWorkspaceWrite,
			WorkspaceRoot: workspaceRootForTest(),
			Enforcement:   sandbox.EnforcementFull,
			Backend:       "bwrap",
		},
		Attestation: sandbox.Attestation{
			Network:    sandbox.NetworkEgressFiltered,
			AttestedBy: "soc-lead",
			Note:       "egress proxy allow-list",
		},
	}
}

// workspaceRootForTest returns an absolute path appropriate for the platform;
// nothing is written during these tests.
func workspaceRootForTest() string {
	if runtime.GOOS == "windows" {
		return `C:\workspace`
	}
	return "/workspace"
}

func TestInterpreterDeniedWithoutGrant(t *testing.T) {
	runner := interpreterRunner(t, confinedGate())
	runner.Policy.Interpreter = false

	_, err := runner.Execute(context.Background(), Request{
		Argv:   []string{"python3", "-c", "print(1)"},
		Target: domain.Target{Host: "example.com"},
	})
	if domain.AsToolError(err).Code != domain.CodePolicyDenied {
		t.Fatalf("code = %q, want policy_denied", domain.AsToolError(err).Code)
	}
}

func TestInterpreterDeniedWithoutSandboxGate(t *testing.T) {
	// No gate means no confinement statement, which is a refusal rather than an
	// implicit grant.
	runner := interpreterRunner(t, nil)

	_, err := runner.Execute(context.Background(), Request{
		Argv:   []string{"python3", "-c", "print(1)"},
		Target: domain.Target{Host: "example.com"},
	})
	if domain.AsToolError(err).Code != domain.CodePolicyDenied {
		t.Fatalf("code = %q, want policy_denied", domain.AsToolError(err).Code)
	}
	if !strings.Contains(err.Error(), "attestation") {
		t.Fatalf("the error should say what is missing, got %v", err)
	}
}

func TestInterpreterDeniedWhenEgressUnconfined(t *testing.T) {
	gate := confinedGate()
	gate.Attestation.Network = sandbox.NetworkUnconfined

	runner := interpreterRunner(t, gate)
	_, err := runner.Execute(context.Background(), Request{
		Argv:   []string{"python3", "-c", "print(1)"},
		Target: domain.Target{Host: "example.com"},
	})
	if domain.AsToolError(err).Code != domain.CodePolicyDenied {
		t.Fatalf("code = %q, want policy_denied", domain.AsToolError(err).Code)
	}
	// The model must learn that the environment, not the target, is the problem.
	if !strings.Contains(err.Error(), "unconfined") {
		t.Fatalf("error should name the network state, got %v", err)
	}
}

func TestInterpreterDeniedWhenSandboxIsOnlyPartial(t *testing.T) {
	gate := confinedGate()
	gate.Policy.Enforcement = sandbox.EnforcementPartial

	runner := interpreterRunner(t, gate)
	_, err := runner.Execute(context.Background(), Request{
		Argv:   []string{"sh", "-c", "id"},
		Target: domain.Target{Host: "example.com"},
	})
	if domain.AsToolError(err).Code != domain.CodePolicyDenied {
		t.Fatalf("code = %q, want policy_denied", domain.AsToolError(err).Code)
	}
	if !strings.Contains(err.Error(), "partially") {
		t.Fatalf("error should explain the enforcement gap, got %v", err)
	}
}

func TestInterpreterRequiresApprovalEvenWhenConfined(t *testing.T) {
	// Confinement bounds the blast radius; it does not make opaque code safe to
	// run unattended. Every script is a human decision.
	runner := interpreterRunner(t, confinedGate())
	runner.Approvals = nil

	_, err := runner.Execute(context.Background(), Request{
		Argv:   []string{"python3", "-c", "print(1)"},
		Target: domain.Target{Host: "example.com"},
	})
	if domain.AsToolError(err).Code != domain.CodeApprovalRequired {
		t.Fatalf("code = %q, want approval_required", domain.AsToolError(err).Code)
	}
}

func TestInterpreterShellMetacharactersAreAllowed(t *testing.T) {
	// A script legitimately contains ";", "|" and ">". The ban applies to
	// non-interpreter commands only; interpreters are gated by confinement.
	gate := confinedGate()
	gate.Policy.Enforcement = sandbox.EnforcementPartial // keep it from running
	runner := interpreterRunner(t, gate)

	classification := runner.Policy.Classify([]string{"sh", "-c", "id; whoami | cat"})
	if classification.Decision == DecisionDeny && strings.Contains(classification.Reason, "metacharacter") {
		t.Fatal("script syntax must not be rejected as a shell metacharacter injection")
	}
}

func TestInterpreterScriptIsRecordedInAudit(t *testing.T) {
	script := ExtractScript([]string{"python3", "-c", "import os; os.getcwd()"})
	if script.Inline != "import os; os.getcwd()" {
		t.Fatalf("Inline = %q", script.Inline)
	}
	if script.SHA256 == "" {
		t.Fatal("the payload digest must be recorded; the code is the real evidence")
	}
	if script.Bytes != len(script.Inline) {
		t.Fatalf("Bytes = %d, want %d", script.Bytes, len(script.Inline))
	}
}

func TestExtractScriptUnderstandsFileInvocation(t *testing.T) {
	script := ExtractScript([]string{"python3", "/opt/tools/scan.py", "--target", "x"})
	if script.File != "/opt/tools/scan.py" {
		t.Fatalf("File = %q", script.File)
	}
	if script.Inline != "" {
		t.Fatalf("Inline should be empty for a file invocation, got %q", script.Inline)
	}
}

func TestDestructiveCodeIsStillDenied(t *testing.T) {
	// Confinement and approval do not license destructive local commands.
	runner := interpreterRunner(t, confinedGate())
	runner.Policy.Ceiling = domain.RiskIntrusive

	_, err := runner.Execute(context.Background(), Request{
		Argv:   []string{"sh", "-c", "rm -rf /"},
		Target: domain.Target{Host: "example.com"},
	})
	if domain.AsToolError(err).Code != domain.CodePolicyDenied {
		t.Fatalf("code = %q, want policy_denied", domain.AsToolError(err).Code)
	}
}

func TestWorkspaceRootPinnedForInterpreters(t *testing.T) {
	gate := confinedGate()
	gate.Policy.Enforcement = sandbox.EnforcementPartial

	// A partial sandbox refuses the call, but the working directory must still
	// be derived from the workspace so a permitted call cannot write to the
	// worker's own installation directory.
	if got := gate.WorkspaceRootFor("/fallback"); got != gate.Policy.WorkspaceRoot {
		t.Fatalf("WorkspaceRootFor = %q, want the sandbox workspace", got)
	}

	// Without a workspace-write policy there is nothing to pin, so the caller
	// fallback is preserved rather than silently replaced.
	readOnly := &SandboxGate{Policy: sandbox.Policy{Mode: sandbox.ModeReadOnly}}
	if got := readOnly.WorkspaceRootFor("/fallback"); got != "/fallback" {
		t.Fatalf("WorkspaceRootFor = %q, want the fallback under read-only", got)
	}
}
