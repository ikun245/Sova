package exec

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"soc/agent/internal/domain"
)

func TestScanToolSubstitutesHostIntoArgv(t *testing.T) {
	// Capture what would be executed instead of running a real tool.
	var captured []string
	runner := newTestRunner(t, nil)
	runner.Lookup = staticLookup("203.0.113.10")

	tool := NewScanTool("http_probe", "desc",
		[]string{"curl", "-sS", "-I", "https://{host_port}/"}, domain.RiskLight, runner)

	// Scope denies before execution, but the argv substitution still happens
	// first; assert on the audit entry, which records the final argv.
	err := func() error {
		_, err := tool.Call(context.Background(), json.RawMessage(`{"host":"example.com","port":8443}`))
		return err
	}()
	if err == nil {
		t.Fatal("port 8443 is not in the authorized port list, so the call must be refused")
	}

	// Re-run with an authorized port so a process would be attempted; the
	// audit entry is what we assert on.
	audit := &recordingAudit{}
	runner2 := newTestRunner(t, audit)
	runner2.Lookup = staticLookup("203.0.113.10")
	tool2 := NewScanTool("http_probe", "desc",
		[]string{"curl", "-sS", "-I", "https://{host_port}/"}, domain.RiskLight, runner2)
	_, _ = tool2.Call(context.Background(), json.RawMessage(`{"host":"example.com","port":443}`))

	if len(audit.entries) == 0 {
		t.Fatal("every call must be audited")
	}
	captured = audit.entries[0].Argv
	joined := strings.Join(captured, " ")
	if !strings.Contains(joined, "https://example.com:443/") {
		t.Fatalf("argv = %v, want the host and port substituted", captured)
	}
}

func TestScanToolRejectsOutOfScopeTarget(t *testing.T) {
	audit := &recordingAudit{}
	runner := newTestRunner(t, audit)
	tool := NewScanTool("port_scan", "desc", []string{"nmap", "-sT", "{host}"}, domain.RiskActive, runner)

	_, err := tool.Call(context.Background(), json.RawMessage(`{"host":"evil.test","port":443}`))
	if !errors.Is(err, ErrDenied) {
		t.Fatalf("error = %v, want ErrDenied", err)
	}
	if len(audit.entries) != 1 || audit.entries[0].Decision != DecisionDeny {
		t.Fatal("a refused target must be recorded as denied")
	}
}

func TestScanToolRequiresHost(t *testing.T) {
	runner := newTestRunner(t, nil)
	tool := NewScanTool("dns_lookup", "desc", []string{"dig", "{host}"}, domain.RiskPassive, runner)

	if _, err := tool.Call(context.Background(), json.RawMessage(`{}`)); err == nil {
		t.Fatal("a missing host must be rejected")
	}
}

func TestScanToolSchemaExposesNoFreeFormFlags(t *testing.T) {
	runner := newTestRunner(t, nil)
	tool := NewScanTool("port_scan", "desc", []string{"nmap", "{host}"}, domain.RiskActive, runner)

	schema := string(tool.Spec().Parameters)
	if strings.Contains(schema, "flag") || strings.Contains(schema, "args") {
		t.Fatal("the schema must not let the model supply arbitrary flags")
	}
	if !strings.Contains(schema, `"host"`) {
		t.Fatal("the schema must require a host")
	}
}

func TestCatalogOnlyExposesClassifiedTools(t *testing.T) {
	runner := newTestRunner(t, nil)
	for _, tool := range Catalog(runner) {
		spec := tool.Spec()
		if spec.Name == "" || spec.Description == "" {
			t.Fatalf("tool %+v is missing a name or description", spec)
		}
		if len(tool.argv) == 0 {
			t.Fatalf("tool %q has no command", spec.Name)
		}
		if _, known := toolRisk[baseName(tool.argv[0])]; !known {
			t.Fatalf("tool %q uses unclassified binary %q", spec.Name, tool.argv[0])
		}
		if spec.Risk != toolRisk[baseName(tool.argv[0])] {
			t.Fatalf("tool %q declares risk %q but its binary is %q", spec.Name, spec.Risk, toolRisk[baseName(tool.argv[0])])
		}
	}
}

func TestCatalogHasNoIntrusiveTool(t *testing.T) {
	runner := newTestRunner(t, nil)
	for _, tool := range Catalog(runner) {
		if tool.Spec().Risk == domain.RiskIntrusive {
			t.Fatalf("tool %q is intrusive; exploitation tooling must be added deliberately, not shipped in the default catalog", tool.Spec().Name)
		}
	}
}
