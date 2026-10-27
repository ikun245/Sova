package exec

import (
	"context"
	"strings"
	"testing"

	"soc/agent/internal/domain"
)

func TestLocalBackendRunsAndReportsExitCode(t *testing.T) {
	outcome, err := LocalBackend{}.Run(context.Background(), CommandSpec{
		Program:   "go",
		Args:      []string{"version"},
		MaxOutput: 4096,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if outcome.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", outcome.ExitCode)
	}
	if !strings.Contains(outcome.Stdout, "go version") {
		t.Fatalf("stdout = %q", outcome.Stdout)
	}
}

func TestLocalBackendCapsOutput(t *testing.T) {
	// A tool that prints more than the cap must be truncated, not buffered in
	// full: a runaway scanner can otherwise exhaust the worker's memory.
	outcome, err := LocalBackend{}.Run(context.Background(), CommandSpec{
		Program:   "go",
		Args:      []string{"env"},
		MaxOutput: 8,
	})
	if err != nil {
		t.Fatalf("Run returned error: %v", err)
	}
	if len(outcome.Stdout) > 8 {
		t.Fatalf("stdout length = %d, want at most 8", len(outcome.Stdout))
	}
	if !outcome.Truncated {
		t.Fatal("Truncated = false, want true")
	}
}

func TestLocalBackendMissingBinaryIsAnError(t *testing.T) {
	_, err := LocalBackend{}.Run(context.Background(), CommandSpec{Program: "soc-no-such-binary-xyz"})
	if err == nil {
		t.Fatal("running a missing binary must return an error")
	}
}

func TestDockerBackendRequiresContainer(t *testing.T) {
	// Fail closed: without a container there is nowhere to run, and pretending
	// otherwise would silently execute on the host instead.
	backend := DockerBackend{}
	if _, err := backend.Run(context.Background(), CommandSpec{Program: "nmap"}); err == nil {
		t.Fatal("Run with no container must fail")
	}
	err := backend.Available(context.Background(), "nmap")
	if err == nil {
		t.Fatal("Available with no container must fail")
	}
	if !strings.Contains(err.Error(), "toolbox") {
		t.Fatalf("error does not name the cause: %v", err)
	}
}

func TestDockerBackendNameIncludesContainer(t *testing.T) {
	if got := (DockerBackend{Container: "soc-toolbox"}).Name(); got != "docker:soc-toolbox" {
		t.Fatalf("Name = %q", got)
	}
	if got := (DockerBackend{}).Name(); got != "docker" {
		t.Fatalf("Name without a container = %q", got)
	}
}

func TestBackendIsRecordedInAudit(t *testing.T) {
	// The audit row must say where the command ran; otherwise a reviewer cannot
	// tell a host execution from a toolbox execution.
	audit := &recordingAudit{}
	runner := NewRunner(Policy{Ceiling: domain.RiskPassive}, testScope(), audit)
	runner.Backend = fakeBackend{name: "docker:soc-toolbox"}

	if _, err := runner.Execute(context.Background(), Request{
		Argv:   []string{"dig", "+short", "example.com"},
		Target: domain.Target{Host: "example.com", Port: 443},
	}); err != nil {
		t.Fatalf("Execute returned error: %v", err)
	}
	if len(audit.entries) != 1 {
		t.Fatalf("audit entries = %d", len(audit.entries))
	}
	if !strings.Contains(audit.entries[0].Sandbox, "backend=docker:soc-toolbox") {
		t.Fatalf("audit sandbox field = %q", audit.entries[0].Sandbox)
	}
}

// fakeBackend proves the runner is not tied to a real process for tests.
type fakeBackend struct{ name string }

func (b fakeBackend) Name() string { return b.name }

func (b fakeBackend) Available(context.Context, string) error { return nil }

func (b fakeBackend) Run(context.Context, CommandSpec) (CommandOutcome, error) {
	return CommandOutcome{Stdout: "ok", ExitCode: 0}, nil
}

func TestInterpreterWorkdirPinsToSandbox(t *testing.T) {
	// Under docker the interpreter must land in the toolbox workspace, not in
	// whatever directory the platform binary happens to be running from.
	backend := DockerBackend{Container: "soc-toolbox", WorkDir: "/work"}
	if got := firstNonEmpty("", backend.workDir()); got != "/work" {
		t.Fatalf("resolved workdir = %q, want /work", got)
	}
	if got := firstNonEmpty("/explicit", backend.workDir()); got != "/explicit" {
		t.Fatalf("explicit workdir must win, got %q", got)
	}
}
