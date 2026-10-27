package room

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"soc/agent/internal/domain"
	"soc/agent/internal/llm"
	"soc/agent/internal/platform"
)

// TestConsultationEndToEnd drives the real contributor against a fake
// Chat-Completions endpoint, so prompt wiring, token accounting, and the
// synthesizer handoff are verified without a vendor account.
func TestConsultationEndToEnd(t *testing.T) {
	var prompts []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
			MaxTokens int   `json:"max_tokens"`
			Tools     []any `json:"tools"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode request: %v", err)
		}
		var combined strings.Builder
		for _, message := range body.Messages {
			combined.WriteString(message.Content)
			combined.WriteString("\n")
		}
		prompts = append(prompts, combined.String())

		if len(body.Tools) != 0 {
			t.Error("a consultation turn must not offer tools")
		}
		if body.MaxTokens != 512 {
			t.Errorf("MaxTokens = %d, want 512", body.MaxTokens)
		}

		// The synthesizer sees the replies; participants do not.
		if strings.Contains(combined.String(), "成员意见") {
			_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"{\"outcome\":\"rework\",\"rationale\":\"IOC is stale per intel\",\"actions\":[\"refresh IOC\"],\"next_owner\":\"triage\"}"}}],"usage":{"prompt_tokens":80,"completion_tokens":20}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"needs fresher intel"}}],"usage":{"prompt_tokens":50,"completion_tokens":10}}`))
	}))
	t.Cleanup(server.Close)

	t.Setenv("E2E_KEY", "k")
	models := platform.ModelsConfig{
		Providers: map[string]platform.ModelProvider{
			"mock": {
				APIFormat: platform.APIChatCompletions,
				BaseURL:   server.URL,
				APIKeyEnv: "E2E_KEY",
				Timeout:   platform.Duration{Duration: 5 * time.Second},
			},
		},
		Profiles: map[string]platform.ModelProfile{
			"m": {ProviderID: "mock", ModelID: "mock-chat", Type: platform.ModelTypeChat, MaxOutputTokens: 512},
		},
		Roles: map[string]string{
			"triage":  "m",
			"summary": "m",
		},
	}

	registry := llm.NewRegistry(models)
	contributor := NewLLMContributor(registry)

	repo := newFakeRoomRepo()
	teams := &fakeTeamRepo{members: []domain.TeamMember{
		{AgentKey: "triage", Duty: "triage", ModelRole: "triage", Enabled: true, Position: 0},
		{AgentKey: "intel", Duty: "intel", ModelRole: "summary", Enabled: true, Position: 1},
	}}
	service := NewService(repo, teams, contributor, DefaultPolicy())
	service.newID = func() (string, error) { return "room-e2e", nil }

	outcome, err := service.Summon(context.Background(), SummonRequest{
		WorkspaceID: "ws-1",
		TeamID:      "team-1",
		Topic:       "stale IOC",
		Trigger:     domain.SummonTriggerStall,
		OpenedBy:    "worker",
		Signals:     domain.StallSignals{StepsUsed: 12, StepBudget: 12},
		Brief: domain.RoomBrief{
			Problem:  "alert references an IOC that intel says expired",
			Evidence: []domain.EvidenceRef{{Kind: "intel_ioc", Ref: "ioc:1", Quote: "expired 30 days ago"}},
			Ask:      "should we trust the IOC",
		},
		Budget: domain.RoomBudget{MaxParticipants: 2, MaxRounds: 1, MaxTokensPerTurn: 512, MaxTotalTokens: 8000},
	})
	if err != nil {
		t.Fatalf("Summon() error = %v", err)
	}

	// 2 participants + 1 synthesis = 3 real HTTP calls.
	if len(prompts) != 3 {
		t.Fatalf("model calls = %d, want 3", len(prompts))
	}
	if outcome.Decision.Outcome != "rework" {
		t.Fatalf("Outcome = %q, want rework", outcome.Decision.Outcome)
	}
	if outcome.Decision.NextOwner != "triage" {
		t.Fatalf("NextOwner = %q", outcome.Decision.NextOwner)
	}
	// 2 x 60 + 1 x 100 = 220
	if outcome.TokensUsed != 220 {
		t.Fatalf("TokensUsed = %d, want 220", outcome.TokensUsed)
	}
	if !strings.Contains(prompts[1], "intel") {
		t.Fatal("the second participant should be prompted with its own duty")
	}
}
