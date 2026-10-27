package exec

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"soc/agent/internal/domain"
)

// CustomRequest runs a caller-supplied executor through the same gates as an
// external command. Built-in tools (HTTP repeater, intruder) use this so they
// cannot bypass scope, approval, rate limiting, or audit just because they do
// not spawn a process.
type CustomRequest struct {
	// ToolName is what the audit row and the approval binding call this action.
	ToolName string
	// Argv is a synthetic command line. It exists so an approval is still bound
	// to the exact action: for HTTP tools it carries method, URL and a body
	// digest, which is what a human reviews.
	Argv []string
	// Target is required for every custom request: there is no safe default.
	Target domain.Target
	// Risk is declared by the tool and is still subject to the ceiling.
	Risk domain.RiskLevel
	// Timeout bounds the whole action, including internal retries.
	Timeout time.Duration
	// ApprovalID authorizes an "ask" decision for this exact Argv and Target.
	ApprovalID string
	// Run performs the action once every gate has passed.
	Run func(ctx context.Context) (Result, error)
}

// ExecuteCustom is Execute for actions that are not a child process.
//
// The ordering is identical to Execute and for the same reasons: policy, then
// scope, then approval, then the action. A tool never gets to decide that its
// own target is fine.
func (r *Runner) ExecuteCustom(ctx context.Context, req CustomRequest) (Result, error) {
	started := r.clock()
	entry := AuditEntry{
		At:         started,
		TicketID:   r.Scope.TicketID,
		ScopeID:    r.Scope.ID,
		Program:    req.ToolName,
		Argv:       append([]string(nil), req.Argv...),
		Target:     req.Target.String(),
		ApprovalID: req.ApprovalID,
	}

	classification := r.Policy.Decide(req.Risk, "")
	entry.Risk = classification.Risk
	entry.Decision = classification.Decision
	entry.Reason = classification.Reason

	if classification.Decision == DecisionDeny {
		r.audit(ctx, entry)
		return Result{Classification: classification}, domain.NewToolError(domain.CodePolicyDenied,
			classification.Reason,
			"do not retry this action; it exceeds the engagement ceiling and needs a new scope").
			WithDetail("tool", req.ToolName).
			WithDetail("risk", string(classification.Risk))
	}

	if req.Run == nil {
		return Result{Classification: classification}, domain.NewToolError(domain.CodeInternal,
			"tool has no executor", "report this as a platform defect")
	}

	// Scope first, approval second: a human is never asked to bless a target
	// the engagement forbids anyway.
	if err := r.checkTarget(ctx, req.Target); err != nil {
		entry.Decision = DecisionDeny
		entry.Reason = err.Error()
		r.audit(ctx, entry)
		return Result{Classification: classification}, err
	}

	if classification.Decision == DecisionAsk {
		if err := r.consumeApproval(ctx, Request{
			Argv:       req.Argv,
			Target:     req.Target,
			ApprovalID: req.ApprovalID,
		}, classification, &entry); err != nil {
			entry.Decision = DecisionAsk
			r.audit(ctx, entry)
			return Result{Classification: classification}, err
		}
	}

	// A built-in tool still respects the engagement's request rate: parallel
	// goroutines or a tight loop must not turn into a flood.
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

	entry.Sandbox = describeBackend(r.backend(), "in-process")
	actionStarted := r.clock()
	result, runErr := req.Run(runCtx)
	duration := r.clock().Sub(actionStarted)

	if result.Classification.Risk == "" {
		result.Classification = classification
	}
	if result.Risk == "" {
		result.Risk = classification.Risk
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		result.TimedOut = true
	}
	result.Duration = duration

	entry.ExitCode = result.ExitCode
	entry.Duration = duration
	entry.OutputSize = len(result.Stdout) + len(result.Stderr)
	entry.Truncated = result.Truncated
	entry.TimedOut = result.TimedOut
	r.audit(context.WithoutCancel(ctx), entry)

	if result.TimedOut {
		return result, domain.NewToolError(domain.CodeTimeout,
			fmt.Sprintf("%s exceeded its %s budget", req.ToolName, timeout),
			"retry with a longer timeout, or narrow the request").
			WithDetail("tool", req.ToolName).
			WithDetail("target", entry.Target)
	}
	if runErr != nil {
		return result, runErr
	}
	return result, nil
}

// checkTarget validates a target for an action that has no argv to infer
// intent from. Every custom request must name its target explicitly.
func (r *Runner) checkTarget(ctx context.Context, target domain.Target) error {
	if strings.TrimSpace(target.Host) == "" {
		return domain.NewToolError(domain.CodeInvalidArgument,
			"this tool requires an explicit target so its scope can be checked",
			"include the host you intend to act on")
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

	return r.checkResolvedAddress(ctx, target.Host)
}

// checkResolvedAddress blocks a permitted hostname from reaching an address the
// engagement would not authorize directly (DNS rebinding, internal pivots).
func (r *Runner) checkResolvedAddress(ctx context.Context, host string) error {
	host = strings.TrimSpace(host)
	if ip := net.ParseIP(host); ip != nil {
		// An explicitly declared CIDR wins, exactly as it does for a resolved
		// hostname. Without this, a lab engagement that authorizes 10.0.0.0/8
		// could never target an address inside it, which makes the scope
		// declaration useless.
		if err := rejectForbiddenAddress(ip, host); err != nil {
			if r.Scope.AllowsIP(ip) {
				return nil
			}
			return err
		}
		return nil
	}

	lookup := r.Lookup
	if lookup == nil {
		lookup = defaultLookup
	}
	addresses, err := lookup(ctx, host)
	if err != nil {
		return domain.WrapToolError(domain.CodeInvalidArgument,
			fmt.Sprintf("could not resolve %q before connecting", host),
			"verify the hostname, or target the IP directly if the engagement lists it", err).
			WithDetail("target", host)
	}
	if len(addresses) == 0 {
		return domain.NewToolError(domain.CodeInvalidArgument,
			fmt.Sprintf("resolve %q returned no addresses", host),
			"verify the hostname resolves").
			WithDetail("target", host)
	}
	for _, ip := range addresses {
		if err := rejectForbiddenAddress(ip, host); err != nil {
			if r.Scope.AllowsIP(ip) {
				continue
			}
			return err
		}
	}
	return nil
}
