package platform

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const validModelsYAML = `
providers:
  deepseek:
    api_format: openai-chat-completions
    base_url: https://api.deepseek.com
    api_key_env: TEST_LLM_KEY
    timeout: 30s
    max_retries: 2
    max_tokens_field: max_completion_tokens
  local:
    base_url: http://127.0.0.1:8081
    base_urls:
      rerank: http://127.0.0.1:8082

profiles:
  triage-default:
    provider_id: deepseek
    model_id: deepseek-chat
    type: chat
    context_window: 64000
    max_output_tokens: 8192
    capabilities: [tools, json_schema]
    cost:
      input: 0.27
      output: 1.1
  embed-default:
    provider_id: local
    model_id: bge-m3
    type: embedding
    dimension: 1024
  rerank-default:
    provider_id: local
    model_id: bge-reranker-v2-m3
    type: rerank

roles:
  triage: triage-default
  embedding: embed-default
  rerank: rerank-default
`

func writeModelsFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "models.yaml")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write models file: %v", err)
	}
	return path
}

func TestLoadModelsConfigResolvesChatRole(t *testing.T) {
	t.Setenv("TEST_LLM_KEY", "test-key")
	config, err := LoadModelsConfigFile(writeModelsFile(t, validModelsYAML))
	if err != nil {
		t.Fatalf("LoadModelsConfigFile() error = %v", err)
	}

	resolved, err := config.Resolve("triage")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if resolved.Type != ModelTypeChat {
		t.Fatalf("Type = %q, want chat", resolved.Type)
	}
	if resolved.APIFormat != APIChatCompletions {
		t.Fatalf("APIFormat = %q, want %q", resolved.APIFormat, APIChatCompletions)
	}
	if resolved.ModelID != "deepseek-chat" {
		t.Fatalf("ModelID = %q", resolved.ModelID)
	}
	if resolved.APIKey != "test-key" {
		t.Fatal("APIKey should be read from the referenced environment variable")
	}
	if resolved.Timeout != 30*time.Second {
		t.Fatalf("Timeout = %v, want 30s", resolved.Timeout)
	}
	if resolved.MaxTokensField != "max_completion_tokens" {
		t.Fatalf("MaxTokensField = %q", resolved.MaxTokensField)
	}
	if !resolved.Supports("tools") || resolved.Supports("streaming") {
		t.Fatal("Supports() should reflect only declared capabilities")
	}
	if resolved.Cost == nil || resolved.Cost.Input != 0.27 {
		t.Fatalf("Cost = %+v, want parsed input price", resolved.Cost)
	}
}

func TestResolveAppliesTypeDefaultsAndPerTypeEndpoints(t *testing.T) {
	config, err := LoadModelsConfigFile(writeModelsFile(t, validModelsYAML))
	if err != nil {
		t.Fatalf("LoadModelsConfigFile() error = %v", err)
	}

	embedding, err := config.Resolve("embedding")
	if err != nil {
		t.Fatalf("Resolve(embedding) error = %v", err)
	}
	if embedding.APIFormat != APIEmbeddings {
		t.Fatalf("APIFormat = %q, want the embedding default %q", embedding.APIFormat, APIEmbeddings)
	}
	if embedding.Dimension != 1024 {
		t.Fatalf("Dimension = %d, want 1024", embedding.Dimension)
	}

	rerank, err := config.Resolve("rerank")
	if err != nil {
		t.Fatalf("Resolve(rerank) error = %v", err)
	}
	if rerank.APIFormat != APIRerankTEI {
		t.Fatalf("APIFormat = %q, want %q", rerank.APIFormat, APIRerankTEI)
	}
	// base_urls overrides base_url for this type only.
	if rerank.BaseURL != "http://127.0.0.1:8082" {
		t.Fatalf("BaseURL = %q, want the rerank-specific endpoint", rerank.BaseURL)
	}
	if rerank.Timeout != 60*time.Second {
		t.Fatalf("Timeout = %v, want the 60s default", rerank.Timeout)
	}
}

func TestValidateRejectsRoleBoundToWrongModelType(t *testing.T) {
	config := ModelsConfig{
		Providers: map[string]ModelProvider{"p": {BaseURL: "http://x"}},
		Profiles: map[string]ModelProfile{
			"emb": {ProviderID: "p", ModelID: "bge-m3", Type: ModelTypeEmbedding, Dimension: 1024},
		},
		Roles: map[string]string{"triage": "emb"},
	}
	err := config.Validate()
	if err == nil {
		t.Fatal("binding triage to an embedding model must be rejected")
	}
	if !strings.Contains(err.Error(), "requires") {
		t.Fatalf("error should explain the type mismatch, got %v", err)
	}
}

func TestValidateRequiresProfileType(t *testing.T) {
	config := ModelsConfig{
		Providers: map[string]ModelProvider{"p": {BaseURL: "http://x"}},
		Profiles:  map[string]ModelProfile{"m": {ProviderID: "p", ModelID: "some-model"}},
	}
	if err := config.Validate(); err == nil {
		t.Fatal("a profile without a type must be rejected")
	}
}

func TestValidateRejectsEmbeddingWithoutDimension(t *testing.T) {
	config := ModelsConfig{
		Providers: map[string]ModelProvider{"p": {BaseURL: "http://x"}},
		Profiles: map[string]ModelProfile{
			"emb": {ProviderID: "p", ModelID: "bge-m3", Type: ModelTypeEmbedding},
		},
	}
	if err := config.Validate(); err == nil {
		t.Fatal("an embedding model without a dimension must be rejected")
	}
}

func TestValidateRejectsUnknownModality(t *testing.T) {
	config := ModelsConfig{
		Providers: map[string]ModelProvider{"p": {BaseURL: "http://x"}},
		Profiles: map[string]ModelProfile{
			"v": {ProviderID: "p", ModelID: "m", Type: ModelTypeVision, Input: []string{"smell"}},
		},
	}
	if err := config.Validate(); err == nil {
		t.Fatal("an unknown input modality must be rejected")
	}
}

func TestValidateAcceptsVisionWithImageInput(t *testing.T) {
	config := ModelsConfig{
		Providers: map[string]ModelProvider{"p": {BaseURL: "http://x"}},
		Profiles: map[string]ModelProfile{
			"v": {ProviderID: "p", ModelID: "m", Type: ModelTypeVision, Input: []string{"text", "image"}},
		},
		Roles: map[string]string{"summary": "v"},
	}
	if err := config.Validate(); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}
	resolved, err := config.Resolve("summary")
	if err != nil {
		t.Fatalf("Resolve() error = %v", err)
	}
	if !resolved.AcceptsModality("image") || resolved.AcceptsModality("audio") {
		t.Fatal("AcceptsModality should reflect the declared input list")
	}
}

func TestEmbeddingModelCannotServeChatRole(t *testing.T) {
	config := ModelsConfig{
		Providers: map[string]ModelProvider{"p": {BaseURL: "http://x"}},
		Profiles: map[string]ModelProfile{
			"emb": {ProviderID: "p", ModelID: "bge", Type: ModelTypeEmbedding, Dimension: 1024},
		},
		Roles: map[string]string{"summary": "emb"},
	}
	if err := config.Validate(); err == nil {
		t.Fatal("an embedding model must not satisfy a chat role")
	}
}

func TestValidateRejectsUnsupportedProtocol(t *testing.T) {
	config := ModelsConfig{
		Providers: map[string]ModelProvider{"p": {APIFormat: "anthropic-messages", BaseURL: "http://x"}},
	}
	if err := config.Validate(); err == nil {
		t.Fatal("unsupported protocols must be rejected instead of guessed")
	}
}

func TestValidateRejectsUnknownProviderReference(t *testing.T) {
	config := ModelsConfig{
		Providers: map[string]ModelProvider{"a": {BaseURL: "http://x"}},
		Profiles:  map[string]ModelProfile{"p": {ProviderID: "missing", ModelID: "m", Type: ModelTypeChat}},
	}
	if err := config.Validate(); err == nil {
		t.Fatal("expected unknown provider reference to be rejected")
	}
}

func TestValidateRejectsUnknownRoleProfile(t *testing.T) {
	config := ModelsConfig{
		Providers: map[string]ModelProvider{"a": {BaseURL: "http://x"}},
		Profiles:  map[string]ModelProfile{},
		Roles:     map[string]string{"triage": "nope"},
	}
	if err := config.Validate(); err == nil {
		t.Fatal("expected unknown role profile to be rejected")
	}
}

func TestResolveFailsWhenCredentialEnvIsEmpty(t *testing.T) {
	t.Setenv("TEST_LLM_KEY", "")
	config, err := LoadModelsConfigFile(writeModelsFile(t, validModelsYAML))
	if err != nil {
		t.Fatalf("LoadModelsConfigFile() error = %v", err)
	}
	_, err = config.Resolve("triage")
	if err == nil {
		t.Fatal("expected a missing credential to be rejected")
	}
	if strings.Contains(err.Error(), "test-key") {
		t.Fatal("error must never echo credential values")
	}
	if !strings.Contains(err.Error(), "TEST_LLM_KEY") {
		t.Fatalf("error should name the variable, got %v", err)
	}
}

func TestLoadModelsConfigWithoutEnvIsNotAnError(t *testing.T) {
	t.Setenv("SOC_MODELS_CONFIG", "")
	_, err := LoadModelsConfig()
	if !errors.Is(err, ErrModelsNotConfigured) {
		t.Fatalf("error = %v, want ErrModelsNotConfigured", err)
	}
}

func TestLoadModelsConfigRejectsInvalidDuration(t *testing.T) {
	bad := `
providers:
  a:
    base_url: http://x
    timeout: not-a-duration
`
	if _, err := LoadModelsConfigFile(writeModelsFile(t, bad)); err == nil {
		t.Fatal("expected an invalid duration to be rejected")
	}
}
