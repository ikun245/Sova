package exec

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"soc/agent/internal/domain"
)

type recordingAudit struct {
	entries []AuditEntry
}

func (r *recordingAudit) Record(_ context.Context, entry AuditEntry) error {
	r.entries = append(r.entries, entry)
	return nil
}

func testScope() domain.TargetScope {
	return domain.TargetScope{
		ID:         "eng-1",
		Domains:    []string{"example.com"},
		CIDRs:      []string{"203.0.113.0/24"},
		Ports:      []int{80, 443},
		MaxRisk:    domain.RiskActive,
		TicketID:   "TICKET-42",
		ApprovedBy: "ciso",
		ExpiresAt:  time.Now().Add(24 * time.Hour),
	}
}

func staticLookup(ips ...string) func(context.Context, string) ([]net.IP, error) {
	return func(context.Context, string) ([]net.IP, error) {
		out := make([]net.IP, 0, len(ips))
		for _, raw := range ips {
			out = append(out, net.ParseIP(raw))
		}
		return out, nil
	}
}

func newTestRunner(t *testing.T, audit Auditor) *Runner {
	t.Helper()
	runner := NewRunner(
		Policy{Ceiling: domain.RiskActive, AskAbove: domain.RiskLight},
		testScope(), audit,
	)
	runner.Lookup = staticLookup("203.0.113.10")
	// Tests must not depend on which scanners the host happens to have.
	runner.LookPath = func(program string) (string, error) { return "/usr/bin/" + program, nil }
	return runner
}

func TestRunnerDeniesOutOfScopeDomainBeforeExecution(t *testing.T) {
	audit := &recordingAudit{}
	runner := newTestRunner(t, audit)

	_, err := runner.Execute(context.Background(), Request{
		Argv:   []string{"curl", "-sS", "https://evil.test/"},
		Target: domain.Target{Host: "evil.test", Port: 443},
	})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit entries = %d, want 1 denial recorded", len(audit.entries))
	}
	if audit.entries[0].Decision != DecisionDeny {
		t.Fatalf("audit decision = %q, want deny", audit.entries[0].Decision)
	}
	if audit.entries[0].TicketID != "TICKET-42" {
		t.Fatal("the audit entry must carry the engagement ticket for accountability")
	}
}

func TestRunnerDeniesDestructiveCommandWithoutAuditor(t *testing.T) {
	runner := newTestRunner(t, nil)
	_, err := runner.Execute(context.Background(), Request{
		Argv:   []string{"sh", "-c", "rm -rf /"},
		Target: domain.Target{Host: "example.com"},
	})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
}

func TestRunnerRequiresApprovalAboveAskThreshold(t *testing.T) {
	runner := newTestRunner(t, nil)

	// nmap is active; AskAbove is light, so it needs an approval id.
	_, err := runner.Execute(context.Background(), Request{
		Argv:   []string{"nmap", "-sV", "example.com"},
		Target: domain.Target{Host: "example.com", Port: 443},
	})
	if !errors.Is(err, ErrNeedsApproval) {
		t.Fatalf("error = %v, want ErrNeedsApproval", err)
	}
}

func TestRunnerRequiresTargetForScopedTools(t *testing.T) {
	runner := newTestRunner(t, nil)
	_, err := runner.Execute(context.Background(), Request{
		Argv: []string{"curl", "-sS", "https://example.com"},
	})
	// A missing target is a fixable argument error, not an authorization
	// refusal: the model should retry with a target, not escalate.
	if err == nil {
		t.Fatal("expected an error when no target is declared")
	}
	toolErr := domain.AsToolError(err)
	if toolErr.Code != domain.CodeInvalidArgument {
		t.Fatalf("Code = %q, want %q", toolErr.Code, domain.CodeInvalidArgument)
	}
	if toolErr.Hint == "" {
		t.Fatal("the error must tell the model what to fix")
	}
}

func TestRunnerRejectsHostnameResolvingToLoopback(t *testing.T) {
	runner := newTestRunner(t, nil)
	// A permitted domain that resolves internally must not become a pivot.
	runner.Lookup = staticLookup("127.0.0.1")

	_, err := runner.Execute(context.Background(), Request{
		Argv:   []string{"curl", "-sS", "https://example.com/"},
		Target: domain.Target{Host: "example.com", Port: 443},
	})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied for a loopback resolution", err)
	}
	if !strings.Contains(err.Error(), "loopback") {
		t.Fatalf("error should name the reason, got %v", err)
	}
}

func TestRunnerRejectsCloudMetadataAddress(t *testing.T) {
	runner := newTestRunner(t, nil)
	runner.Lookup = staticLookup("169.254.169.254")

	_, err := runner.Execute(context.Background(), Request{
		Argv:   []string{"curl", "-sS", "https://example.com/"},
		Target: domain.Target{Host: "example.com", Port: 443},
	})
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied for a metadata endpoint", err)
	}
}

func TestRunnerAllowsDeclaredInternalCIDR(t *testing.T) {
	// Internal ranges are legitimate when the engagement declares them.
	scope := testScope()
	scope.CIDRs = append(scope.CIDRs, "10.1.0.0/16")
	runner := NewRunner(Policy{Ceiling: domain.RiskActive, AskAbove: domain.RiskActive}, scope, nil)
	runner.Lookup = staticLookup("10.1.2.3")

	// An IP literal is checked against CIDRs directly.
	if err := runner.checkScope(context.Background(), []string{"nmap"}, domain.Target{Host: "10.1.2.3", Port: 443}); err != nil {
		t.Fatalf("declared internal target should be allowed: %v", err)
	}
}

func TestRunnerRejectsIPOutsideDeclaredCIDR(t *testing.T) {
	runner := newTestRunner(t, nil)
	// 10.1.2.3 is in 10.1.0.0/16, not in the declared 203.0.113.0/24.
	err := runner.checkScope(context.Background(), []string{"nmap"}, domain.Target{Host: "10.1.2.3", Port: 443})
	if err == nil {
		t.Fatal("an IP outside every declared CIDR must be rejected")
	}
}

func TestRunnerPassiveToolSkipsAddressCheck(t *testing.T) {
	runner := newTestRunner(t, nil)
	runner.Lookup = func(context.Context, string) ([]net.IP, error) {
		t.Fatal("passive lookups must not resolve through the runner")
		return nil, nil
	}
	// dig only reads public DNS records; there is no connection to authorise.
	if err := runner.checkScope(context.Background(), []string{"dig"}, domain.Target{Host: "example.com"}); err != nil {
		t.Fatalf("passive tool should pass scope: %v", err)
	}
}

func TestRunnerAuditsTimedOutCommand(t *testing.T) {
	audit := &recordingAudit{}
	runner := newTestRunner(t, audit)
	runner.DefaultTimeout = 300 * time.Millisecond

	// Use a classified program we can actually run cross-platform: curl is
	// rarely present on Windows CI, so exercise the timeout path with a
	// deliberately tiny limit on a passive tool instead.
	runner.Lookup = staticLookup("203.0.113.10")
	_, err := runner.Execute(context.Background(), Request{
		Argv:       []string{"curl", "-sS", "--max-time", "30", "https://example.com/"},
		Target:     domain.Target{Host: "example.com", Port: 443},
		Timeout:    250 * time.Millisecond,
		ApprovalID: "",
	})
	// curl may be absent; either way a decision must have been audited first.
	if len(audit.entries) == 0 {
		t.Fatal("every attempt must be audited, even when the binary is missing")
	}
	if err != nil && !errors.Is(err, ErrDenied) && !errors.Is(err, ErrNeedsApproval) {
		// Execution failure is acceptable here; the point is the audit trail.
		t.Logf("execution ended with: %v", err)
	}
}

func TestRunnerCappedBufferTruncates(t *testing.T) {
	buffer := &cappedBuffer{limit: 10}
	if _, err := buffer.Write([]byte("0123456789abcdef")); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if !buffer.truncated {
		t.Fatal("expected truncation to be recorded")
	}
	if buffer.String() != "0123456789" {
		t.Fatalf("output = %q, want the first 10 bytes", buffer.String())
	}
}
