package platform

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// ErrModelsNotConfigured means no models file was supplied. Callers should
// treat it as "LLM features disabled", not as a fatal error.
var ErrModelsNotConfigured = errors.New("models configuration is not provided")

// ModelType classifies a model by the contract it satisfies, not by vendor.
// The type decides which protocol is used and which port the adapter
// implements, so a role can never be bound to a mismatched model.
type ModelType string

const (
	// ModelTypeChat is a text chat model that can call tools.
	ModelTypeChat ModelType = "chat"
	// ModelTypeVision is a chat model that also accepts image input.
	ModelTypeVision ModelType = "vision"
	// ModelTypeEmbedding produces dense vectors; requires a dimension.
	ModelTypeEmbedding ModelType = "embedding"
	// ModelTypeRerank scores query/document pairs.
	ModelTypeRerank ModelType = "rerank"
	// ModelTypeASR transcribes audio.
	ModelTypeASR ModelType = "asr"
)

var validModelTypes = map[ModelType]bool{
	ModelTypeChat:      true,
	ModelTypeVision:    true,
	ModelTypeEmbedding: true,
	ModelTypeRerank:    true,
	ModelTypeASR:       true,
}

// Protocol identifiers. Only implemented protocols are accepted.
const (
	APIChatCompletions = "openai-chat-completions"
	APIEmbeddings      = "openai-embeddings"
	APIRerankTEI       = "tei-rerank"
)

// defaultAPIFormat is the protocol used for a model type when a provider does
// not name one explicitly.
var defaultAPIFormat = map[ModelType]string{
	ModelTypeChat:      APIChatCompletions,
	ModelTypeVision:    APIChatCompletions,
	ModelTypeEmbedding: APIEmbeddings,
	ModelTypeRerank:    APIRerankTEI,
}

// implementedAPIFormats lists protocols this build can actually serve. A
// declared-but-unimplemented protocol is rejected at validation time instead
// of failing on the first request.
var implementedAPIFormats = map[string]bool{
	APIChatCompletions: true,
	APIEmbeddings:      true,
	APIRerankTEI:       true,
}

// roleRequiredType pins a business role to a model type. This is what makes a
// misconfiguration (e.g. binding triage to an embedding model) a startup error
// rather than a confusing runtime failure.
var roleRequiredType = map[string]ModelType{
	"triage":    ModelTypeChat,
	"summary":   ModelTypeChat,
	"embedding": ModelTypeEmbedding,
	"rerank":    ModelTypeRerank,
	// Agent duties. Every one of them is a chat role: a duty decides tools and
	// prompt, never the protocol, so binding a duty to an embedding model must
	// fail at startup rather than on the first tool call.
	"agent.plan":    ModelTypeChat,
	"agent.recon":   ModelTypeChat,
	"agent.web":     ModelTypeChat,
	"agent.exploit": ModelTypeChat,
	"agent.critic":  ModelTypeChat,
	"agent.report":  ModelTypeChat,
}

// typeSatisfies reports whether a profile of type actual can serve a role that
// requires want. Vision models are chat models with image input, so they
// satisfy chat roles; an embedding model never satisfies a chat role.
func typeSatisfies(actual, want ModelType) bool {
	if actual == want {
		return true
	}
	return want == ModelTypeChat && actual == ModelTypeVision
}

// ModelsConfig is the three-layer model configuration: connections, models,
// and the roles that use them.
type ModelsConfig struct {
	Providers map[string]ModelProvider `yaml:"providers"`
	Profiles  map[string]ModelProfile  `yaml:"profiles"`
	Roles     map[string]string        `yaml:"roles"`
}

// ModelProvider describes a connection: auth and transport policy. It holds no
// model id, because one endpoint often serves several models of different
// types with different paths and limits.
type ModelProvider struct {
	// APIFormat is the default protocol for this provider.
	APIFormat string `yaml:"api_format"`
	// BaseURL is the default endpoint for this provider.
	BaseURL string `yaml:"base_url"`
	// APIFormats overrides APIFormat per model type, for gateways that expose
	// chat and embeddings on different paths or shapes.
	APIFormats map[ModelType]string `yaml:"api_formats"`
	// BaseURLs overrides BaseURL per model type, mirroring the same need.
	BaseURLs  map[ModelType]string `yaml:"base_urls"`
	APIKeyEnv string               `yaml:"api_key_env"`
	Timeout   Duration             `yaml:"timeout"`
	// MaxRetries counts retries after the first attempt.
	MaxRetries int `yaml:"max_retries"`
	// MaxTokensField lets an endpoint that rejects "max_tokens" (some
	// reasoning models) use "max_completion_tokens" instead.
	MaxTokensField string `yaml:"max_tokens_field"`
}

// ModelCost is priced per million tokens. Keeping it in config makes cost
// attribution possible without querying a vendor price list.
type ModelCost struct {
	Input      float64 `yaml:"input"`
	Output     float64 `yaml:"output"`
	CacheRead  float64 `yaml:"cache_read"`
	CacheWrite float64 `yaml:"cache_write"`
	Currency   string  `yaml:"currency"`
}

// ModelProfile describes one model: what it is, its limits, and its declared
// abilities. Capabilities are claims verified by an explicit check, never
// inferred from "compatible" appearing in a vendor name.
type ModelProfile struct {
	ProviderID string    `yaml:"provider_id"`
	ModelID    string    `yaml:"model_id"`
	Type       ModelType `yaml:"type"`
	// Aliases are additional ids that resolve to this model (dated snapshots,
	// vendor-prefixed names on gateways).
	Aliases []string `yaml:"aliases"`
	// Input lists accepted modalities: text, image, audio.
	Input           []string `yaml:"input"`
	ContextWindow   int      `yaml:"context_window"`
	MaxOutputTokens int      `yaml:"max_output_tokens"`
	// Dimension is the embedding width; required for embedding models so an
	// index is never built against an unknown vector width.
	Dimension    int        `yaml:"dimension"`
	Cost         *ModelCost `yaml:"cost"`
	Capabilities []string   `yaml:"capabilities"`
	Deprecated   bool       `yaml:"deprecated"`
}

// ResolvedModel is a role's complete, ready-to-use model configuration.
type ResolvedModel struct {
	Role            string
	ProviderID      string
	Type            ModelType
	APIFormat       string
	BaseURL         string
	APIKey          string
	ModelID         string
	Input           []string
	ContextWindow   int
	MaxOutputTokens int
	Dimension       int
	Cost            *ModelCost
	Capabilities    []string
	Timeout         time.Duration
	MaxRetries      int
	MaxTokensField  string
}

// Supports reports whether a profile declared a capability.
func (r ResolvedModel) Supports(capability string) bool {
	for _, c := range r.Capabilities {
		if strings.EqualFold(c, capability) {
			return true
		}
	}
	return false
}

// AcceptsModality reports whether the model accepts an input modality.
func (r ResolvedModel) AcceptsModality(modality string) bool {
	for _, m := range r.Input {
		if strings.EqualFold(m, modality) {
			return true
		}
	}
	return false
}

// Duration parses YAML values such as "60s" into a time.Duration.
type Duration struct {
	time.Duration
}

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	var raw string
	if err := value.Decode(&raw); err != nil {
		return fmt.Errorf("duration must be a string like \"60s\": %w", err)
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		d.Duration = 0
		return nil
	}
	parsed, err := time.ParseDuration(raw)
	if err != nil {
		return fmt.Errorf("invalid duration %q: %w", raw, err)
	}
	d.Duration = parsed
	return nil
}

// LoadModelsConfig reads the models file named by SOC_MODELS_CONFIG. When the
// variable is empty it returns ErrModelsNotConfigured so the rest of the
// service can keep running without model features.
func LoadModelsConfig() (ModelsConfig, error) {
	path := strings.TrimSpace(os.Getenv("SOC_MODELS_CONFIG"))
	if path == "" {
		return ModelsConfig{}, ErrModelsNotConfigured
	}
	return LoadModelsConfigFile(path)
}

func LoadModelsConfigFile(path string) (ModelsConfig, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return ModelsConfig{}, fmt.Errorf("read models config: %w", err)
	}
	var config ModelsConfig
	if err := yaml.Unmarshal(raw, &config); err != nil {
		return ModelsConfig{}, fmt.Errorf("parse models config %q: %w", path, err)
	}
	if err := config.Validate(); err != nil {
		return ModelsConfig{}, fmt.Errorf("invalid models config %q: %w", path, err)
	}
	return config, nil
}

// Validate checks types, references, and protocol support without touching
// secrets, so every message is safe to log.
func (m ModelsConfig) Validate() error {
	if len(m.Providers) == 0 {
		return errors.New("models.providers must not be empty")
	}
	for id, provider := range m.Providers {
		if strings.TrimSpace(provider.BaseURL) == "" && len(provider.BaseURLs) == 0 {
			return fmt.Errorf("provider %q: base_url or base_urls is required", id)
		}
		if strings.TrimSpace(provider.APIFormat) != "" {
			if err := checkAPIFormat(provider.APIFormat); err != nil {
				return fmt.Errorf("provider %q: %w", id, err)
			}
		}
		for modelType, format := range provider.APIFormats {
			if !validModelTypes[modelType] {
				return fmt.Errorf("provider %q: unknown model type %q in api_formats", id, modelType)
			}
			if err := checkAPIFormat(format); err != nil {
				return fmt.Errorf("provider %q (type %s): %w", id, modelType, err)
			}
		}
		for modelType := range provider.BaseURLs {
			if !validModelTypes[modelType] {
				return fmt.Errorf("provider %q: unknown model type %q in base_urls", id, modelType)
			}
		}
	}

	for id, profile := range m.Profiles {
		if err := profile.validate(id, m.Providers); err != nil {
			return err
		}
	}

	for role, profileID := range m.Roles {
		profile, ok := m.Profiles[profileID]
		if !ok {
			return fmt.Errorf("role %q: unknown profile %q", role, profileID)
		}
		if required, ok := roleRequiredType[role]; ok && !typeSatisfies(profile.Type, required) {
			return fmt.Errorf("role %q requires a %q model, but profile %q is %q",
				role, required, profileID, profile.Type)
		}
	}
	return nil
}

func (p ModelProfile) validate(id string, providers map[string]ModelProvider) error {
	if strings.TrimSpace(p.ModelID) == "" {
		return fmt.Errorf("profile %q: model_id is required", id)
	}
	if p.Type == "" {
		return fmt.Errorf("profile %q: type is required (chat, vision, embedding, rerank, asr)", id)
	}
	if !validModelTypes[p.Type] {
		return fmt.Errorf("profile %q: unknown type %q", id, p.Type)
	}
	if _, ok := providers[p.ProviderID]; !ok {
		return fmt.Errorf("profile %q: unknown provider_id %q", id, p.ProviderID)
	}
	if p.ContextWindow < 0 || p.MaxOutputTokens < 0 || p.Dimension < 0 {
		return fmt.Errorf("profile %q: limits must not be negative", id)
	}
	// An embedding index built on an unknown width cannot be validated against
	// stored vectors, so require the dimension up front.
	if p.Type == ModelTypeEmbedding && p.Dimension <= 0 {
		return fmt.Errorf("profile %q: embedding models require a positive dimension", id)
	}
	for _, modality := range p.Input {
		switch strings.ToLower(strings.TrimSpace(modality)) {
		case "text", "image", "audio", "video":
		default:
			return fmt.Errorf("profile %q: unknown input modality %q", id, modality)
		}
	}
	return nil
}

func checkAPIFormat(format string) error {
	if !implementedAPIFormats[format] {
		return fmt.Errorf("unsupported api_format %q (supported: %s, %s, %s)",
			format, APIChatCompletions, APIEmbeddings, APIRerankTEI)
	}
	return nil
}

// Resolve binds a role to its profile and provider, applies per-type
// overrides, and reads the credential from the environment. Error messages
// name the variable but never the secret.
func (m ModelsConfig) Resolve(role string) (ResolvedModel, error) {
	profileID, ok := m.Roles[role]
	if !ok {
		return ResolvedModel{}, fmt.Errorf("role %q is not configured", role)
	}
	profile, ok := m.Profiles[profileID]
	if !ok {
		return ResolvedModel{}, fmt.Errorf("role %q references unknown profile %q", role, profileID)
	}
	provider, ok := m.Providers[profile.ProviderID]
	if !ok {
		return ResolvedModel{}, fmt.Errorf("profile %q references unknown provider %q", profileID, profile.ProviderID)
	}
	if required, ok := roleRequiredType[role]; ok && !typeSatisfies(profile.Type, required) {
		return ResolvedModel{}, fmt.Errorf("role %q requires a %q model, but profile %q is %q",
			role, required, profileID, profile.Type)
	}

	apiFormat := provider.APIFormats[profile.Type]
	if apiFormat == "" {
		apiFormat = provider.APIFormat
	}
	if apiFormat == "" {
		apiFormat = defaultAPIFormat[profile.Type]
	}
	if apiFormat == "" {
		return ResolvedModel{}, fmt.Errorf("profile %q: no api_format for model type %q", profileID, profile.Type)
	}
	if err := checkAPIFormat(apiFormat); err != nil {
		return ResolvedModel{}, fmt.Errorf("profile %q: %w", profileID, err)
	}

	baseURL := provider.BaseURLs[profile.Type]
	if baseURL == "" {
		baseURL = provider.BaseURL
	}
	if strings.TrimSpace(baseURL) == "" {
		return ResolvedModel{}, fmt.Errorf("provider %q: no base_url for model type %q",
			profile.ProviderID, profile.Type)
	}

	apiKey := ""
	if provider.APIKeyEnv != "" {
		apiKey = strings.TrimSpace(os.Getenv(provider.APIKeyEnv))
		if apiKey == "" {
			return ResolvedModel{}, fmt.Errorf("provider %q: environment variable %s is empty",
				profile.ProviderID, provider.APIKeyEnv)
		}
	}

	timeout := provider.Timeout.Duration
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	maxTokensField := strings.TrimSpace(provider.MaxTokensField)
	if maxTokensField == "" {
		maxTokensField = "max_tokens"
	}

	return ResolvedModel{
		Role:            role,
		ProviderID:      profile.ProviderID,
		Type:            profile.Type,
		APIFormat:       apiFormat,
		BaseURL:         baseURL,
		APIKey:          apiKey,
		ModelID:         profile.ModelID,
		Input:           profile.Input,
		ContextWindow:   profile.ContextWindow,
		MaxOutputTokens: profile.MaxOutputTokens,
		Dimension:       profile.Dimension,
		Cost:            profile.Cost,
		Capabilities:    profile.Capabilities,
		Timeout:         timeout,
		MaxRetries:      provider.MaxRetries,
		MaxTokensField:  maxTokensField,
	}, nil
}
