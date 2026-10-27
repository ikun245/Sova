package exec

import (
	"fmt"

	"soc/agent/internal/domain"
)

// classifyInterpreter decides whether one interpreter invocation may run.
//
// Interpreters are never auto-allowed, even when both the filesystem policy and
// the egress attestation are in place. Two reasons:
//   - the code is opaque, so no argument check can predict what it does
//   - a script's destinations are chosen at runtime, not on the command line
//
// So the unit of trust is the single script, and a human sees each one.
func (p Policy) classifyInterpreter(base string) Classification {
	if !p.Interpreter {
		return Classification{
			Risk:     domain.RiskCodeExecution,
			Decision: DecisionDeny,
			Reason: fmt.Sprintf("%s is a general-purpose interpreter; this engagement does not enable code execution "+
				"because a script's network destinations cannot be verified from its command line", base),
		}
	}

	if !domain.RiskCodeExecution.AtMost(p.Ceiling) {
		return Classification{
			Risk:     domain.RiskCodeExecution,
			Decision: DecisionDeny,
			Reason:   fmt.Sprintf("code execution exceeds this engagement's ceiling (%s)", p.Ceiling),
		}
	}

	return Classification{
		Risk:     domain.RiskCodeExecution,
		Decision: DecisionAsk,
		Reason: fmt.Sprintf("%s runs arbitrary code, so every invocation needs approval; "+
			"the script's behaviour cannot be inferred from the command line", base),
	}
}
