package room

import (
	"context"
	"errors"
	"strings"
	"testing"

	"soc/agent/internal/domain"
	"soc/agent/internal/llm"
	"soc/agent/internal/platform"
)

func newFakeModel(content string, inputTokens, outputTokens int) *llm.Fake {
	model := llm.NewFake("fake-model")
	model.Queue(domain.CompletionResponse{
		Content: content,
		Usage:   domain.Usage{InputTokens: inputTokens, OutputTokens: outputTokens},
	})
	return model
}

func TestLLMContributorDoesNotOfferTools(t *testing.T) {
	model := newFakeModel("my view", 100, 20)
	contributor := NewLLMContributor(StaticResolver{Model: model})

	_, err := contributor.Ask(context.Background(), TurnRequest{
		RoomID:    "room-1",
		AgentKey:  "triage",
		Duty:      "triage",
		ModelRole: "triage",
		Topic:     "is this alert real",
		Role:      TurnParticipant,
		Brief:     domain.RoomBrief{Problem: "conflicting evidence"},
		MaxTokens: 512,
	})
	if err != nil {
		t.Fatalf("Ask() error = %v", err)
	}

	requests := model.Requests()
	if len(requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(requests))
	}
	if len(requests[0].Tools) != 0 {
		t.Fatal("a consultation turn must not offer tools; otherwise it can start new work")
	}
	if requests[0].MaxTokens != 512 {
		t.Fatalf("MaxTokens = %d, want 512", requests[0].MaxTokens)
	}
}

func TestLLMContributorClampsToModelOutputLimit(t *testing.T) {
	model := newFakeModel("ok", 10, 5)
	// Declare a small output ceiling so the room's larger request is clamped.
	resolver := fixedResolver{model: model, resolved: platform.ResolvedModel{
		Role: "triage", Type: platform.ModelTypeChat, MaxOutputTokens: 256,
	}}
	contributor := NewLLMContributor(resolver)

	if _, err := contributor.Ask(context.Background(), TurnRequest{
		AgentKey: "triage", ModelRole: "triage", Role: TurnParticipant, MaxTokens: 4096,
	}); err != nil {
		t.Fatalf("Ask() error = %v", err)
	}
	if got := model.Requests()[0].MaxTokens; got != 256 {
		t.Fatalf("MaxTokens = %d, want it clamped to the model limit 256", got)
	}
}

func TestLLMContributorCountsBothTokenDirections(t *testing.T) {
	model := newFakeModel("view", 120, 30)
	contributor := NewLLMContributor(StaticResolver{Model: model})

	result, err := contributor.Ask(context.Background(), TurnRequest{
		AgentKey: "triage", ModelRole: "triage", Role: TurnParticipant,
	})
	if err != nil {
		t.Fatalf("Ask() error = %v", err)
	}
	if result.Tokens != 150 {
		t.Fatalf("Tokens = %d, want 150 (input + output)", result.Tokens)
	}
}

func TestLLMContributorPromptsDifferByDuty(t *testing.T) {
	duties := []string{"triage", "hunting", "intel", "critic", "reporter"}
	seen := map[string]bool{}

	for _, duty := range duties {
		model := newFakeModel("ok", 1, 1)
		contributor := NewLLMContributor(StaticResolver{Model: model})
		if _, err := contributor.Ask(context.Background(), TurnRequest{
			AgentKey: duty, Duty: duty, ModelRole: "triage", Role: TurnParticipant,
		}); err != nil {
			t.Fatalf("Ask(%s) error = %v", duty, err)
		}
		system := model.Requests()[0].Messages[0].Content
		if seen[system] {
			t.Fatalf("duty %q produced the same system prompt as another duty", duty)
		}
		seen[system] = true
	}
}

func TestLLMContributorSynthesizerSeesReplies(t *testing.T) {
	model := newFakeModel(`{"outcome":"proceed"}`, 50, 10)
	contributor := NewLLMContributor(StaticResolver{Model: model})

	if _, err := contributor.Ask(context.Background(), TurnRequest{
		AgentKey: "critic", Duty: "critic", ModelRole: "triage", Role: TurnSynthesizer,
		Topic: "t",
		Brief: domain.RoomBrief{Problem: "p"},
		Replies: []TurnResult{
			{AgentKey: "triage", Text: "it is real"},
			{AgentKey: "intel", Text: "IOC is stale"},
		},
	}); err != nil {
		t.Fatalf("Ask() error = %v", err)
	}

	prompt := model.Requests()[0].Messages[1].Content
	for _, expected := range []string{"it is real", "IOC is stale", "triage", "intel"} {
		if !strings.Contains(prompt, expected) {
			t.Fatalf("synthesizer prompt is missing %q", expected)
		}
	}
	if !strings.Contains(model.Requests()[0].Messages[0].Content, "JSON") {
		t.Fatal("synthesizer must be instructed to return JSON")
	}
}

func TestLLMContributorPropagatesModelErrors(t *testing.T) {
	model := llm.NewFake("fake")
	model.QueueError(errors.New("upstream 500"))
	contributor := NewLLMContributor(StaticResolver{Model: model})

	if _, err := contributor.Ask(context.Background(), TurnRequest{
		AgentKey: "triage", ModelRole: "triage", Role: TurnParticipant,
	}); err == nil {
		t.Fatal("a model failure must surface so the room can mark the agent skipped")
	}
}

func TestLLMContributorUsesParticipantModelRole(t *testing.T) {
	resolver := &recordingResolver{}
	contributor := NewLLMContributor(resolver)

	if _, err := contributor.Ask(context.Background(), TurnRequest{
		AgentKey: "critic", Duty: "critic", ModelRole: "triage-strong", Role: TurnParticipant,
	}); err != nil {
		t.Fatalf("Ask() error = %v", err)
	}
	if len(resolver.roles) != 1 || resolver.roles[0] != "triage-strong" {
		t.Fatalf("roles = %v, want [triage-strong]; each member may bind a different model", resolver.roles)
	}
}

type fixedResolver struct {
	model    domain.LLM
	resolved platform.ResolvedModel
}

func (f fixedResolver) ForRole(string) (domain.LLM, platform.ResolvedModel, error) {
	return f.model, f.resolved, nil
}

type recordingResolver struct {
	roles []string
}

func (r *recordingResolver) ForRole(role string) (domain.LLM, platform.ResolvedModel, error) {
	r.roles = append(r.roles, role)
	model := llm.NewFake("fake")
	model.Queue(domain.CompletionResponse{Content: "ok"})
	return model, platform.ResolvedModel{Role: role, Type: platform.ModelTypeChat}, nil
}
