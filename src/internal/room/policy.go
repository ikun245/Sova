package room

import (
	"fmt"
	"strings"

	"soc/agent/internal/domain"
)

// Policy decides whether a summon is justified. It is deliberately dumb and
// deterministic: the expensive decision must not itself cost a model call.
type Policy struct {
	// MinSignalsForAgentRequest is how many objective stall signals must
	// corroborate a model's own "I need help" request. Without this, an agent
	// can escape hard work by claiming to be stuck.
	MinSignalsForAgentRequest int
}

func DefaultPolicy() Policy {
	return Policy{MinSignalsForAgentRequest: 1}
}

// Authorization is the policy's verdict, kept separate from the signals so the
// audit trail records why a room was allowed to open.
type Authorization struct {
	Reasons []string
}

// Authorize returns an error when a summon is not justified.
func (p Policy) Authorize(trigger domain.SummonTrigger, agentRequested bool, signals domain.StallSignals) (Authorization, error) {
	reasons := signals.Evaluate()

	switch trigger {
	case domain.SummonTriggerUser:
		// A human deliberately interrupting always wins; that is the whole
		// point of the manual escalation path.
		return Authorization{Reasons: reasons}, nil

	case domain.SummonTriggerStall:
		if len(reasons) == 0 {
			return Authorization{}, fmt.Errorf("room: stall summon rejected: no objective stall signal (steps %d/%d, repeated_tools %d, confidence %.2f, missing_evidence %d)",
				signals.StepsUsed, signals.StepBudget, signals.RepeatedToolCalls, signals.Confidence, signals.MissingEvidence)
		}
		return Authorization{Reasons: reasons}, nil

	case domain.SummonTriggerAgent:
		if !agentRequested {
			return Authorization{}, fmt.Errorf("room: agent_request summon requires the agent to ask for help")
		}
		minimum := p.MinSignalsForAgentRequest
		if minimum <= 0 {
			minimum = 1
		}
		if len(reasons) < minimum {
			return Authorization{}, fmt.Errorf(
				"room: agent_request summon rejected: needs %d corroborating signal(s), found %d; a self-reported block is not enough",
				minimum, len(reasons))
		}
		return Authorization{Reasons: reasons}, nil

	default:
		return Authorization{}, fmt.Errorf("room: unknown summon trigger %q", trigger)
	}
}

// sanitizeTopic keeps room titles bounded so they stay usable in lists and logs.
func sanitizeTopic(topic string) string {
	topic = strings.TrimSpace(topic)
	if topic == "" {
		return "untitled consultation"
	}
	if len(topic) > 200 {
		return topic[:200]
	}
	return topic
}
