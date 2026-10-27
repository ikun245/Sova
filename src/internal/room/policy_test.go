package room

import (
	"testing"

	"soc/agent/internal/domain"
)

func TestPolicyAuthorize(t *testing.T) {
	stalled := domain.StallSignals{StepsUsed: 12, StepBudget: 12}
	healthy := domain.StallSignals{StepsUsed: 3, StepBudget: 12, Confidence: 0.9, ConfidenceFloor: 0.75}

	tests := []struct {
		name           string
		trigger        domain.SummonTrigger
		agentRequested bool
		signals        domain.StallSignals
		wantErr        bool
	}{
		{
			name:    "user may always interrupt",
			trigger: domain.SummonTriggerUser,
			signals: healthy,
		},
		{
			name:    "stall with budget exhaustion is allowed",
			trigger: domain.SummonTriggerStall,
			signals: stalled,
		},
		{
			name:    "stall without any signal is rejected",
			trigger: domain.SummonTriggerStall,
			signals: healthy,
			wantErr: true,
		},
		{
			name:           "agent request with corroboration is allowed",
			trigger:        domain.SummonTriggerAgent,
			agentRequested: true,
			signals:        stalled,
		},
		{
			name:           "agent request without corroboration is rejected",
			trigger:        domain.SummonTriggerAgent,
			agentRequested: true,
			signals:        healthy,
			wantErr:        true,
		},
		{
			name:    "agent trigger without the agent asking is rejected",
			trigger: domain.SummonTriggerAgent,
			signals: stalled,
			wantErr: true,
		},
	}

	policy := DefaultPolicy()
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := policy.Authorize(tc.trigger, tc.agentRequested, tc.signals)
			if tc.wantErr && err == nil {
				t.Fatal("expected rejection")
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("unexpected rejection: %v", err)
			}
		})
	}
}

func TestStallSignalsEvaluate(t *testing.T) {
	tests := []struct {
		name    string
		signals domain.StallSignals
		want    string
	}{
		{"step budget", domain.StallSignals{StepsUsed: 5, StepBudget: 5}, domain.ReasonStepBudget},
		{"repeated tool calls", domain.StallSignals{RepeatedToolCalls: 3}, domain.ReasonRepeatedToolCall},
		{"low confidence", domain.StallSignals{Confidence: 0.3, ConfidenceFloor: 0.75}, domain.ReasonLowConfidence},
		{"missing evidence", domain.StallSignals{MissingEvidence: 2}, domain.ReasonMissingEvidence},
		{"contradiction", domain.StallSignals{Contradictions: 2}, domain.ReasonContradiction},
		{"tool errors", domain.StallSignals{ToolErrors: 3}, domain.ReasonToolErrors},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			reasons := tc.signals.Evaluate()
			found := false
			for _, reason := range reasons {
				if reason == tc.want {
					found = true
				}
			}
			if !found {
				t.Fatalf("reasons = %v, want %q", reasons, tc.want)
			}
		})
	}
}

func TestHealthyAgentHasNoStallReason(t *testing.T) {
	signals := domain.StallSignals{
		StepsUsed: 2, StepBudget: 12,
		Confidence: 0.9, ConfidenceFloor: 0.75,
		MissingEvidence: 1, Contradictions: 0, RepeatedToolCalls: 1,
	}
	if reasons := signals.Evaluate(); len(reasons) != 0 {
		t.Fatalf("reasons = %v, want none for a productive agent", reasons)
	}
}

func TestUnassessedConfidenceIsNotLowConfidence(t *testing.T) {
	// Confidence 0 means "not assessed yet"; treating it as low would let
	// every fresh task summon a room before doing any work.
	signals := domain.StallSignals{Confidence: 0, ConfidenceFloor: 0.75}
	if reasons := signals.Evaluate(); len(reasons) != 0 {
		t.Fatalf("reasons = %v, want none", reasons)
	}
}
