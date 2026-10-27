package exec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"soc/agent/internal/domain"
)

// Backend is where an authorized command actually runs. It is the only part of
// the executor that differs between a laptop, a container, and a Kali toolbox:
// policy, scope, approval, rate limiting and audit must stay identical across
// all of them, so switching backend must never change a security decision.
type Backend interface {
	// Name identifies the backend in audit rows, e.g. "local" or "docker:toolbox".
	Name() string
	// Available reports whether a program exists in the execution environment,
	// so an approval is never spent on a command that cannot run.
	Available(ctx context.Context, program string) error
	// Run executes and returns bounded output. It must honour ctx.
	Run(ctx context.Context, spec CommandSpec) (CommandOutcome, error)
}

// CommandSpec is one resolved command. It is deliberately flat: a backend must
// not need to understand risk, scope, or approvals to run it.
type CommandSpec struct {
	Program   string
	Args      []string
	WorkDir   string
	MaxOutput int
	// Timeout is passed to backends that can bound the process on the remote
	// side (docker), where cancelling the client does not stop the tool.
	Timeout time.Duration
}

// CommandOutcome is what the backend observed.
type CommandOutcome struct {
	Stdout    string
	Stderr    string
	ExitCode  int
	Truncated bool
	TimedOut  bool
}

// LocalBackend runs commands as direct children of this process.
type LocalBackend struct{}

func (LocalBackend) Name() string { return "local" }

func (LocalBackend) Available(_ context.Context, program string) error {
	if _, err := exec.LookPath(program); err != nil {
		return fmt.Errorf("%s not found on PATH: %w", program, err)
	}
	return nil
}

func (LocalBackend) Run(ctx context.Context, spec CommandSpec) (CommandOutcome, error) {
	// #nosec G204 -- the program and arguments come from a policy-classified
	// argv, not from a shell string; Policy rejects metacharacters by default.
	cmd := exec.CommandContext(ctx, spec.Program, spec.Args...)
	if spec.WorkDir != "" {
		cmd.Dir = spec.WorkDir
	}
	// A minimal environment avoids leaking the worker's credentials into a
	// target-facing process.
	cmd.Env = minimalEnv()

	stdout := &cappedBuffer{limit: spec.MaxOutput}
	stderr := &cappedBuffer{limit: spec.MaxOutput}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	outcome := CommandOutcome{
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		Truncated: stdout.truncated || stderr.truncated,
	}
	if cmd.ProcessState != nil {
		outcome.ExitCode = cmd.ProcessState.ExitCode()
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		outcome.TimedOut = true
	}
	// A non-zero exit is a normal outcome for a scanner (open ports, no
	// matches), so it is reported through ExitCode rather than as an error.
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) && !outcome.TimedOut {
		return outcome, err
	}
	return outcome, nil
}

// DockerBackend runs commands inside a long-lived toolbox container. On Windows
// and macOS this is the only way to use Kali: Docker Desktop is already a Linux
// virtual machine, so the tool sees a real Linux userland without the platform
// image having to carry every scanner.
//
// Security note: this backend shells out to the docker CLI, which means the
// process needs access to the Docker socket. That access is effectively root on
// the host, so mount it only on a development machine or a dedicated Kali host,
// never into a container exposed to an untrusted network.
type DockerBackend struct {
	// Container is the toolbox service name, e.g. "toolbox".
	Container string
	// DockerBin is the CLI to invoke; defaults to "docker".
	DockerBin string
	// WorkDir is the default working directory inside the container.
	WorkDir string
	// NetworkCheck, when set, is consulted before every run so a toolbox that
	// lost its egress attestation fails closed instead of silently scanning.
	NetworkCheck func() error
}

func (b DockerBackend) Name() string {
	if b.Container == "" {
		return "docker"
	}
	return "docker:" + b.Container
}

func (b DockerBackend) binary() string {
	if strings.TrimSpace(b.DockerBin) != "" {
		return b.DockerBin
	}
	return "docker"
}

func (b DockerBackend) workDir() string {
	if strings.TrimSpace(b.WorkDir) != "" {
		return b.WorkDir
	}
	return "/work"
}

// Available asks the container, not the host. A tool installed on the laptop
// but missing from the toolbox must still be reported as unavailable, otherwise
// the check would be meaningless.
func (b DockerBackend) Available(ctx context.Context, program string) error {
	if strings.TrimSpace(b.Container) == "" {
		return domain.NewToolError(domain.CodeBinaryMissing,
			"no toolbox container is configured",
			"operator action required: set SOC_TOOLBOX_CONTAINER to the toolbox service name")
	}
	// "$1" keeps the program name a positional parameter, so a name containing
	// shell syntax can never be interpreted.
	args := []string{"exec", b.Container, "sh", "-c", `command -v "$1" >/dev/null 2>&1`, "--", program}
	cmd := exec.CommandContext(ctx, b.binary(), args...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s is not installed in the toolbox container: %w", program, err)
	}
	return nil
}

func (b DockerBackend) Run(ctx context.Context, spec CommandSpec) (CommandOutcome, error) {
	if strings.TrimSpace(b.Container) == "" {
		return CommandOutcome{}, domain.NewToolError(domain.CodeBinaryMissing,
			"no toolbox container is configured",
			"operator action required: set SOC_TOOLBOX_CONTAINER to the toolbox service name")
	}
	if b.NetworkCheck != nil {
		if err := b.NetworkCheck(); err != nil {
			return CommandOutcome{}, err
		}
	}

	args := []string{"exec"}
	if dir := firstNonEmpty(spec.WorkDir, b.workDir()); dir != "" {
		args = append(args, "-w", dir)
	}
	args = append(args, b.Container)

	// Bound the process inside the container too. Cancelling the docker client
	// on timeout leaves the tool running, which would keep sending traffic to a
	// target after the engagement budget was spent.
	if spec.Timeout > 0 {
		seconds := int(spec.Timeout.Seconds())
		if seconds < 1 {
			seconds = 1
		}
		args = append(args, "timeout", "-k", "5s", strconv.Itoa(seconds)+"s")
	}
	args = append(args, spec.Program)
	args = append(args, spec.Args...)

	// #nosec G204 -- argv is policy-classified and passed as arguments to docker
	// exec, never through a shell. The only shell inside the container is the
	// fixed `command -v "$1"` form used by Available.
	cmd := exec.CommandContext(ctx, b.binary(), args...)
	stdout := &cappedBuffer{limit: spec.MaxOutput}
	stderr := &cappedBuffer{limit: spec.MaxOutput}
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	outcome := CommandOutcome{
		Stdout:    stdout.String(),
		Stderr:    stderr.String(),
		Truncated: stdout.truncated || stderr.truncated,
	}
	if cmd.ProcessState != nil {
		outcome.ExitCode = cmd.ProcessState.ExitCode()
	}
	// 124 is `timeout`'s own code; 125 is a docker daemon error and must not be
	// mistaken for the tool's exit status.
	if outcome.ExitCode == 124 {
		outcome.TimedOut = true
	}
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		outcome.TimedOut = true
	}
	var exitErr *exec.ExitError
	if err != nil && !errors.As(err, &exitErr) && !outcome.TimedOut {
		return outcome, err
	}
	return outcome, nil
}

// minimalEnv is only used by LocalBackend: a container supplies its own
// environment, and forwarding the host PATH there would be wrong.
func minimalEnv() []string {
	if runtime.GOOS == "windows" {
		return []string{
			"PATH=" + os.Getenv("PATH"),
			"SystemRoot=" + os.Getenv("SystemRoot"),
			"TEMP=" + os.Getenv("TEMP"),
			"TMP=" + os.Getenv("TMP"),
		}
	}
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"LANG=C.UTF-8",
	}
}

// cappedBuffer keeps at most limit bytes and records that it dropped the rest,
// so a multi-gigabyte tool output cannot exhaust the worker's memory.
type cappedBuffer struct {
	buf       bytes.Buffer
	limit     int
	truncated bool
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	written := len(p)
	if b.limit <= 0 {
		return written, nil
	}
	remaining := b.limit - b.buf.Len()
	if remaining <= 0 {
		b.truncated = true
		return written, nil
	}
	if len(p) > remaining {
		b.buf.Write(p[:remaining])
		b.truncated = true
		return written, nil
	}
	b.buf.Write(p)
	return written, nil
}

func (b *cappedBuffer) String() string {
	return b.buf.String()
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
