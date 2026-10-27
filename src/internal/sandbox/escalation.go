package sandbox

import (
	"fmt"
	"strings"
)

// widerModes is a closed ladder. It is checked at execution time and never
// written into a tool schema, so a model cannot discover or guess a mode the
// deployment did not offer.
//
// Strictly wider only: read-only may widen to either other mode, workspace-write
// only to full access. A narrower target is never a valid escalation, because
// "widening" that narrows is a contradiction the caller should see as an error.
var widerModes = map[Mode][]Mode{
	ModeReadOnly:       {ModeWorkspaceWrite, ModeFullAccess},
	ModeWorkspaceWrite: {ModeFullAccess},
	ModeFullAccess:     nil,
}

// ErrInvalidEscalation means the requested mode is not strictly wider than the
// current one.
type ErrInvalidEscalation struct {
	From Mode
	To   Mode
}

func (e *ErrInvalidEscalation) Error() string {
	return fmt.Sprintf("cannot escalate sandbox from %q to %q: escalation must be strictly wider", e.From, e.To)
}

// EscalationRequest is a model's request to re-run one call under a wider mode.
type EscalationRequest struct {
	From Mode
	To   Mode
	// Justification is free text from the model. It is recorded verbatim for
	// audit and never parsed to make a decision.
	Justification string
}

// Validate rejects a request that is malformed or not actually wider. It does
// not decide whether approval is needed.
func (r EscalationRequest) Validate() error {
	if !r.To.Valid() {
		return fmt.Errorf("unknown target mode %q", r.To)
	}
	if r.To == r.From {
		// Asking for the current mode is not an escalation. The caller should
		// simply retry the call as-is; returning an error prevents a pointless
		// approval prompt.
		return fmt.Errorf("requested mode %q is already in effect; retry without escalation", r.From)
	}
	for _, wider := range widerModes[r.From] {
		if r.To == wider {
			if strings.TrimSpace(r.Justification) == "" {
				return fmt.Errorf("escalating to %q requires a justification", r.To)
			}
			return nil
		}
	}
	return &ErrInvalidEscalation{From: r.From, To: r.To}
}

// NeedsApproval reports whether the validated escalation requires a human
// decision. Every widening does: a wider sandbox is a larger blast radius.
func (r EscalationRequest) NeedsApproval() bool {
	return r.From != r.To
}

// EscalationOutcome is what the caller should do next.
type EscalationOutcome struct {
	// Mode is the mode to use for the retry. It equals From when no escalation
	// is needed.
	Mode Mode
	// RequiresApproval means a human must approve before Mode applies.
	RequiresApproval bool
	// Justification is echoed into the audit record unchanged.
	Justification string
}

// Resolve validates a request and states whether approval is needed.
//
// The requested mode applies to this call only. Nothing is persisted, so a
// one-off widening cannot become the new default by accident.
//
// current is authoritative: the caller's From field is ignored and overwritten,
// because validating against a caller-supplied origin would let a stale or
// malicious value skip the strictly-wider check.
func Resolve(current Mode, request EscalationRequest) (EscalationOutcome, error) {
	request.From = current

	if request.To == "" || request.To == current {
		return EscalationOutcome{Mode: current}, nil
	}
	if err := request.Validate(); err != nil {
		return EscalationOutcome{}, err
	}
	return EscalationOutcome{
		Mode:             request.To,
		RequiresApproval: request.NeedsApproval(),
		Justification:    request.Justification,
	}, nil
}

// DenialMarker is the exact token a tool result carries when the sandbox refused
// a file effect. Keeping one marker means a model does not have to pattern-match
// prose to notice that confinement, not the target, was the problem.
func DenialMarker(mode Mode) string {
	return fmt.Sprintf("[sandbox: file access denied under %s mode]", mode)
}

// EscalationHint tells the model how to proceed after a denial. It is only
// included when the deployment offers an escalation path; promising a path that
// does not exist would make the model loop.
func EscalationHint(current Mode, available bool) string {
	if !available || len(widerModes[current]) == 0 {
		return ""
	}
	widest := widerModes[current][len(widerModes[current])-1]
	return fmt.Sprintf("if this path is inside your workspace, request sandbox_permissions=%q "+
		"with a justification so a human can approve it for this one call", widest)
}
