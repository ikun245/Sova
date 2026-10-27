package llm

import (
	"testing"

	"soc/agent/internal/platform"
)

func testModelsConfig(t *testing.T) platform.ModelsConfig {
	t.Helper()
	t.Setenv("REG_TEST_KEY", "key")
	return platform.ModelsConfig{
		Providers: map[string]platform.ModelProvider{
			"p": {
				APIFormat: platform.APIChatCompletions,
				BaseURL:   "http://127.0.0.1:9",
				APIKeyEnv: "REG_TEST_KEY",
			},
		},
		Profiles: map[string]platform.ModelProfile{
			"shared": {ProviderID: "p", ModelID: "shared-model", Type: platform.ModelTypeChat},
			"other":  {ProviderID: "p", ModelID: "other-model", Type: platform.ModelTypeChat},
			"emb":    {ProviderID: "p", ModelID: "emb-model", Type: platform.ModelTypeEmbedding, Dimension: 8},
		},
		Roles: map[string]string{
			"triage":    "shared",
			"summary":   "shared",
			"critic":    "other",
			"embedding": "emb",
		},
	}
}

func TestRegistryReusesAdapterForSharedProfile(t *testing.T) {
	registry := NewRegistry(testModelsConfig(t))

	first, firstResolved, err := registry.ForRole("triage")
	if err != nil {
		t.Fatalf("ForRole(triage) error = %v", err)
	}
	second, secondResolved, err := registry.ForRole("summary")
	if err != nil {
		t.Fatalf("ForRole(summary) error = %v", err)
	}

	if first != second {
		t.Fatal("roles sharing a profile must share one adapter instance")
	}
	if firstResolved.Role != "triage" || secondResolved.Role != "summary" {
		t.Fatal("each role should still report its own resolved metadata")
	}
}

func TestRegistrySeparatesDistinctProfiles(t *testing.T) {
	registry := NewRegistry(testModelsConfig(t))

	triage, _, err := registry.ForRole("triage")
	if err != nil {
		t.Fatalf("ForRole(triage) error = %v", err)
	}
	critic, _, err := registry.ForRole("critic")
	if err != nil {
		t.Fatalf("ForRole(critic) error = %v", err)
	}
	if triage == critic {
		t.Fatal("distinct profiles must not share an adapter")
	}
}

func TestRegistryRejectsUnknownRole(t *testing.T) {
	registry := NewRegistry(testModelsConfig(t))
	if _, _, err := registry.ForRole("nonexistent"); err == nil {
		t.Fatal("an unconfigured role must be rejected")
	}
}

func TestRegistryRejectsEmptyRole(t *testing.T) {
	registry := NewRegistry(testModelsConfig(t))
	if _, _, err := registry.ForRole("  "); err == nil {
		t.Fatal("an empty role must be rejected instead of defaulting silently")
	}
}

func TestRegistryRejectsRoleWithoutAdapter(t *testing.T) {
	registry := NewRegistry(testModelsConfig(t))
	// Embedding models are a valid configuration but have no chat adapter yet,
	// so resolving the role must fail loudly rather than return a wrong type.
	if _, _, err := registry.ForRole("embedding"); err == nil {
		t.Fatal("a role whose model type has no adapter must fail instead of silently substituting another model")
	}
}

func TestNewFromResolvedRejectsEmbeddingProfile(t *testing.T) {
	_, err := NewFromResolved(platform.ResolvedModel{
		Role:      "embedding",
		Type:      platform.ModelTypeEmbedding,
		APIFormat: platform.APIEmbeddings,
		BaseURL:   "http://127.0.0.1:9",
		ModelID:   "bge-m3",
		Dimension: 1024,
	})
	if err == nil {
		t.Fatal("NewFromResolved must refuse to build a chat adapter for an embedding profile")
	}
}
