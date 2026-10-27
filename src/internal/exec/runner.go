package exec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"time"

	"soc/agent/internal/domain"
)

// Aliases keep Go callers ergonomic while every failure now carries a stable
// code the model can branch on.
var (
	ErrDenied        = domain.ErrDenied
	ErrNeedsApproval = domain.ErrNeedsApproval
)

// AuditEntry records one decision, whether or not a process ran. Audit rows are
// the evidence that authorization was enforced in code rather than by prompt.
type AuditEntry struct {
	At         time.Time
	TicketID   string
	ScopeID    string
	Program    string
	Argv       []string
	Target     string
	Risk       domain.RiskLevel
	Decision   Decision
	Reason     string
	ExitCode   int
	Duration   time.Duration
	OutputSize int
	Truncated  bool
	TimedOut   bool
	ApprovalID string
	// Script is set for interpreter calls. The code is the payload, so an audit
	// record without it cannot be reviewed later.
	Script *ScriptInfo
	// Sandbox records the confinement in force, so a reviewer sees what the
	// process was actually allowed to do.
	Sandbox string
}

// Auditor receives every decision. Implementations must not block the run
// indefinitely; the runner calls it synchronously but with a bounded payload.
type Auditor interface {
	Record(ctx context.Context, entry AuditEntry) error
}

// Request is one bounded command execution.
type Request struct {
	// Argv is the program and its arguments. No shell interpretation happens
	// unless the Policy explicitly enables it.
	Argv []string
	// Target is the destination the command acts on. Required for every
	// classified tool so scope can be checked before execution; omitting it is
	// a hard error rather than a silent skip.
	Target domain.Target
	// Timeout bounds the process. Zero uses the runner default.
	Timeout time.Duration
	// ApprovalID records which human approval authorized an "ask" decision.
	ApprovalID string
	// WorkDir confines relative file access for tools that write output.
	WorkDir string
}

// Result is what a completed execution produced.
type Result struct {
	Stdout         string
	Stderr         string
	ExitCode       int
	Duration       time.Duration
	Risk           domain.RiskLevel
	Truncated      bool
	TimedOut       bool
	Classification Classification
}

// Runner executes approved commands inside an authorization scope.
//
// The ordering is deliberate and must not be rearranged: policy → approval →
// scope (including resolution) → execute → audit. Checking scope before policy
// would let an unrecognised binary through; checking scope after starting the
// process would make the check meaningless.
type Runner struct {
	Policy Policy
	Scope  domain.TargetScope
	Audit  Auditor
	// Approvals verifies and spends one-shot approvals. When nil, any "ask"
	// decision is denied: an approval that cannot be checked is not an
	// approval. This is the fail-closed default.
	Approvals domain.ApprovalVerifier
	// MaxOutputBytes caps each stream so a runaway tool cannot exhaust memory.
	MaxOutputBytes int
	// DefaultTimeout applies when a request sets none.
	DefaultTimeout time.Duration
	// Lookup resolves a hostname so the resolved addresses can be checked
	// against the scope. Injectable for tests.
	Lookup func(ctx context.Context, host string) ([]net.IP, error)
	// LookPath confirms a program exists before an approval is spent.
	// Injectable so tests do not depend on which scanners are installed.
	LookPath func(program string) (string, error)
	// Limiter enforces the engagement's request rate. Nil means unlimited,
	// which is only appropriate for single-shot tools.
	Limiter *RateLimiter
	// Sandbox decides whether interpreters may run and where they write.
	// Nil means interpreters are refused entirely.
	Sandbox *SandboxGate
	// Backend decides where the process runs. Nil keeps it local, which is the
	// laptop and CI default; a Kali toolbox is selected with DockerBackend.
	// Switching backend changes no security decision, only the destination.
	Backend Backend
	now     func() time.Time
}

const (
	defaultMaxOutputBytes = 256 << 10 // 256 KiB per stream
	defaultTimeout        = 120 * time.Second
)

func NewRunner(policy Policy, scope domain.TargetScope, auditor Auditor) *Runner {
	return &Runner{
		Policy:         policy,
		Scope:          scope,
		Audit:          auditor,
		MaxOutputBytes: defaultMaxOutputBytes,
		DefaultTimeout: defaultTimeout,
		Lookup:         defaultLookup,
		// LookPath stays nil so the configured Backend decides where to look;
		// set it explicitly only to override that in a test.
		// The engagement's rate applies to every command, not just batch tools:
		// a loop of single curls is still a flood.
		Limiter: NewRateLimiter(scope.MaxRatePerMinute),
		now:     time.Now,
	}
}

// Execute runs one request or refuses it. A non-nil error means nothing ran
// (decision problems) unless the error wraps a process failure, in which case
// the audit entry still records the exit code.
func (r *Runner) Execute(ctx context.Context, req Request) (Result, error) {
	started := r.clock()
	entry := AuditEntry{
		At:         started,
		TicketID:   r.Scope.TicketID,
		ScopeID:    r.Scope.ID,
		Argv:       append([]string(nil), req.Argv...),
		Target:     req.Target.String(),
		ApprovalID: req.ApprovalID,
	}
	if len(req.Argv) > 0 {
		entry.Program = req.Argv[0]
	}

	classification := r.Policy.Classify(req.Argv)
	entry.Risk = classification.Risk
	entry.Decision = classification.Decision
	entry.Reason = classification.Reason

	if classification.Decision == DecisionDeny {
		r.audit(ctx, entry)
		return Result{Classification: classification}, domain.
			NewToolError(domain.CodePolicyDenied, classification.Reason,
				"do not retry this command; choose a different approach or escalate to a human").
			WithDetail("program", baseName(entry.Program)).
			WithDetail("risk", string(classification.Risk))
	}

	// Interpreters are checked before anything else can spend an approval: if
	// the environment cannot confine them, no amount of approval makes the call
	// verifiable, so the model should not even ask.
	if IsInterpreter(req.Argv[0]) {
		if err := r.checkInterpreter(ctx, req, &entry); err != nil {
			entry.Decision = DecisionDeny
			entry.Reason = err.Error()
			r.audit(ctx, entry)
			return Result{Classification: classification}, err
		}
		// Pin the working directory so relative paths land in the writable
		// area instead of the worker's own installation directory.
		if req.WorkDir == "" && r.Sandbox != nil {
			req.WorkDir = r.Sandbox.WorkspaceRootFor("")
		}
	}

	// Scope is checked in code, never delegated to the model or the prompt.
	// It runs before approval on purpose: a human must never be asked to sign
	// off on a target the engagement forbids anyway.
	//
	// An interpreter has no target on its command line, so this check has
	// nothing to compare; its destinations are bounded by the network
	// attestation instead, which checkInterpreter already enforced.
	if !IsInterpreter(req.Argv[0]) {
		if err := r.checkScope(ctx, req.Argv, req.Target); err != nil {
			entry.Decision = DecisionDeny
			entry.Reason = err.Error()
			r.audit(ctx, entry)
			return Result{Classification: classification}, err
		}
	}

	if classification.Decision == DecisionAsk {
		// Check the binary first: spending a human approval on a command that
		// cannot possibly run wastes the approval and misleads the caller.
		if err := r.checkBinaryAvailable(ctx, req.Argv); err != nil {
			entry.Decision = classification.Decision
			entry.Reason = err.Error()
			r.audit(ctx, entry)
			return Result{Classification: classification}, err
		}
		if err := r.consumeApproval(ctx, req, classification, &entry); err != nil {
			entry.Decision = DecisionAsk
			r.audit(ctx, entry)
			return Result{Classification: classification}, err
		}
	}

	return r.run(ctx, req, classification, entry)
}

// checkInterpreter enforces both confinement axes before an approval is spent.
func (r *Runner) checkInterpreter(ctx context.Context, req Request, entry *AuditEntry) error {
	if len(req.Argv) == 0 {
		return domain.NewToolError(domain.CodeInvalidArgument, "empty command", "supply a program and arguments")
	}

	// No gate means no confinement statement, which is a refusal rather than an
	// implicit grant.
	if r.Sandbox == nil {
		return domain.NewToolError(domain.CodePolicyDenied,
			"interpreters are disabled: no sandbox or network attestation is configured",
			"operator action required: configure sandbox policy and record an egress attestation").
			WithDetail("interpreter", baseName(req.Argv[0]))
	}

	if err := r.Sandbox.CheckInterpreter(req.Argv[0]); err != nil {
		return err
	}

	// Record what will run. The code, not the command line, is the payload, so
	// an audit without it cannot be reviewed.
	script := ExtractScript(req.Argv)
	entry.Script = &script
	entry.Sandbox = describeSandbox(r.Sandbox)
	return nil
}

// checkBinaryAvailable confirms the program exists before an approval is spent.
func (r *Runner) checkBinaryAvailable(ctx context.Context, argv []string) error {
	if len(argv) == 0 {
		return domain.NewToolError(domain.CodeInvalidArgument, "empty command", "supply a program and arguments")
	}
	program := argv[0]

	// The check must ask the environment that will actually run the command.
	// Asking the host about a toolbox command (or the reverse) would report a
	// tool as present that the executor cannot start.
	var err error
	switch {
	case r.LookPath != nil:
		_, err = r.LookPath(program)
	default:
		err = r.backend().Available(ctx, program)
	}
	if err != nil {
		return domain.WrapToolError(domain.CodeBinaryMissing,
			program+" is not installed in the execution environment",
			"tell the operator this tool is unavailable; do not substitute a different tool", err).
			WithDetail("program", baseName(program)).
			WithDetail("backend", r.backend().Name())
	}
	return nil
}

// consumeApproval spends a one-shot approval bound to this exact command.
//
// An approval id alone is never enough: it must exist, be approved, be
// unexpired, match this scope/target/argv, and not have been used before. A
// non-empty string passing this gate would make "ask" purely decorative.
func (r *Runner) consumeApproval(ctx context.Context, req Request, classification Classification, entry *AuditEntry) error {
	if strings.TrimSpace(req.ApprovalID) == "" {
		// The exact argv is returned so a caller can request the approval that
		// would authorize this precise action. Without it, a human would have
		// to guess a body digest, and the approval would never match.
		return domain.NewToolError(domain.CodeApprovalRequired, classification.Reason,
			"request human approval with the returned approval_argv, then retry the same action with the approval id").
			WithDetail("target", req.Target.String()).
			WithDetail("risk", string(classification.Risk)).
			WithDetail("approval_argv", string(domain.NormalizeArgv(req.Argv)))
	}

	// Fail closed: without a verifier we cannot prove the approval is real, so
	// the request is refused rather than trusted.
	if r.Approvals == nil {
		return domain.NewToolError(domain.CodeApprovalRequired,
			"approval verification is not configured on this worker",
			"operator action required: wire the approval store before enabling ask-level commands").
			WithDetail("approval_id", req.ApprovalID)
	}

	approval, err := r.Approvals.ConsumeApproval(ctx, domain.ApprovalCheck{
		ApprovalID: req.ApprovalID,
		ScopeID:    r.Scope.ID,
		Target:     req.Target.String(),
		Argv:       domain.NormalizeArgv(req.Argv),
	})
	if err != nil {
		entry.Reason = classification.Reason + " (approval refused: " + err.Error() + ")"
		return err
	}

	entry.Reason = classification.Reason + " (approved by " + approval.DecidedBy + ", approval " + approval.ID + ")"
	entry.ApprovalID = approval.ID
	return nil
}

// checkScope validates the declared target and, for hostnames, the addresses it
// actually resolves to. Without the resolution step, a domain in scope could be
// pointed at an internal address after approval (DNS rebinding).
func (r *Runner) checkScope(ctx context.Context, argv []string, target domain.Target) error {
	if len(argv) == 0 {
		return domain.NewToolError(domain.CodeInvalidArgument, "empty command",
			"supply a program and its arguments")
	}
	program := argv[0]

	if NeedsTarget(program) && strings.TrimSpace(target.Host) == "" {
		return domain.NewToolError(domain.CodeInvalidArgument,
			"this tool requires an explicit target so its scope can be checked",
			"include the host you intend to act on")
	}
	if target.Host == "" {
		return nil
	}

	if err := r.Scope.Allows(target, r.clock()); err != nil {
		var outOfScope *domain.ErrOutOfScope
		if errors.As(err, &outOfScope) {
			hint := "choose a target inside the engagement scope; widening scope requires a human"
			if outOfScope.Expired {
				hint = "the authorization window has ended; a human must issue a new scope"
			}
			return domain.NewToolError(outOfScope.Code(), outOfScope.Reason, hint).
				WithDetail("target", target.String()).
				WithDetail("scope_id", r.Scope.ID)
		}
		return domain.NewToolError(domain.CodeOutOfScope, err.Error(),
			"choose a target inside the engagement scope")
	}

	// Passive lookups read public records; they do not open a connection to
	// the target, so there is no address to verify.
	if IsPassive(program) {
		return nil
	}

	return r.checkResolvedAddress(ctx, target.Host)
}

// rejectForbiddenAddress blocks addresses that are never legitimate engagement
// targets: loopback, link-local (including cloud metadata), and multicast.
func rejectForbiddenAddress(ip net.IP, host string) error {
	var reason string
	switch {
	case ip.IsLoopback():
		reason = "resolves to a loopback address, which is never a valid engagement target"
	case ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast():
		reason = "resolves to a link-local address; cloud metadata endpoints are out of scope"
	case ip.IsUnspecified():
		reason = "resolves to the unspecified address"
	case ip.IsMulticast():
		reason = "resolves to a multicast address"
	default:
		return nil
	}
	return domain.NewToolError(domain.CodeOutOfScope,
		fmt.Sprintf("%s %s (%s)", host, reason, ip),
		"target the public address directly, or declare an internal CIDR in the scope").
		WithDetail("target", host).
		WithDetail("resolved_ip", ip.String())
}

func (r *Runner) run(ctx context.Context, req Request, classification Classification, entry AuditEntry) (Result, error) {
	// Throttle before starting the process: waiting after launch would let the
	// request reach the target at full speed and only slow the bookkeeping.
	if r.Limiter != nil {
		if err := r.Limiter.Wait(ctx); err != nil {
			return Result{Classification: classification}, domain.WrapToolError(
				domain.CodeInternal, "cancelled while waiting for a rate-limit slot",
				"retry once the engagement is active again", err)
		}
	}

	timeout := req.Timeout
	if timeout <= 0 {
		timeout = r.DefaultTimeout
	}
	if timeout <= 0 {
		timeout = defaultTimeout
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// #nosec G204 -- the program and arguments come from a policy-classified
	// argv, not from a shell string; Policy rejects metacharacters by default.
	started := r.clock()
	backend := r.backend()
	outcome, runErr := backend.Run(runCtx, CommandSpec{
		Program:   req.Argv[0],
		Args:      req.Argv[1:],
		WorkDir:   req.WorkDir,
		MaxOutput: r.MaxOutputBytes,
		Timeout:   timeout,
	})
	duration := r.clock().Sub(started)

	result := Result{
		Stdout:         outcome.Stdout,
		Stderr:         outcome.Stderr,
		ExitCode:       outcome.ExitCode,
		Duration:       duration,
		Risk:           classification.Risk,
		Truncated:      outcome.Truncated,
		TimedOut:       outcome.TimedOut,
		Classification: classification,
	}
	entry.Sandbox = describeBackend(backend, entry.Sandbox)
	if result.TimedOut {
		entry.TimedOut = true
	}

	entry.ExitCode = result.ExitCode
	entry.Duration = duration
	entry.OutputSize = len(result.Stdout) + len(result.Stderr)
	entry.Truncated = result.Truncated
	r.audit(context.WithoutCancel(ctx), entry)

	if result.TimedOut {
		return result, domain.NewToolError(domain.CodeTimeout,
			fmt.Sprintf("%s exceeded its %s budget", entry.Program, timeout),
			"retry with a longer timeout, or narrow the target range").
			WithDetail("program", baseName(entry.Program)).
			WithDetail("target", entry.Target)
	}
	if runErr != nil {
		// A missing binary is a deployment problem, not a target problem; the
		// model must not respond by switching targets.
		if errors.Is(runErr, exec.ErrNotFound) {
			return result, domain.WrapToolError(domain.CodeBinaryMissing,
				fmt.Sprintf("%s is not installed in the execution environment", entry.Program),
				"tell the operator this tool is unavailable; do not substitute a different tool", runErr).
				WithDetail("program", baseName(entry.Program)).
				WithDetail("backend", backend.Name())
		}
		return result, domain.WrapToolError(domain.CodeCommandFailed,
			fmt.Sprintf("%s exited with code %d", entry.Program, result.ExitCode),
			"inspect stdout/stderr and adjust the command or the target", runErr).
			WithDetail("program", baseName(entry.Program)).
			WithDetail("exit_code", fmt.Sprintf("%d", result.ExitCode)).
			WithDetail("target", entry.Target)
	}
	return result, nil
}

func (r *Runner) audit(ctx context.Context, entry AuditEntry) {
	if r.Audit == nil {
		return
	}
	// Audit failure must not change the security outcome: a denied command
	// stays denied even if the log write fails.
	_ = r.Audit.Record(ctx, entry)
}

func (r *Runner) clock() time.Time {
	if r.now != nil {
		return r.now()
	}
	return time.Now()
}

// backend returns the configured execution backend, defaulting to local.
func (r *Runner) backend() Backend {
	if r.Backend != nil {
		return r.Backend
	}
	return LocalBackend{}
}

// describeBackend records the execution destination in the audit row, so a
// reviewer can tell whether a command ran on the host or in the toolbox.
func describeBackend(backend Backend, existing string) string {
	name := "backend=" + backend.Name()
	if strings.TrimSpace(existing) == "" {
		return name
	}
	return existing + "; " + name
}

func defaultLookup(ctx context.Context, host string) ([]net.IP, error) {
	resolver := net.DefaultResolver
	return resolver.LookupIP(ctx, "ip", host)
}
