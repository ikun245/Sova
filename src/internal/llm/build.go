package llm

import (
	"fmt"

	"soc/agent/internal/domain"
	"soc/agent/internal/platform"
)

// NewFromResolved builds the adapter for a resolved role. The model type, not
// the vendor name, selects the port, so a chat role can never receive an
// embedding adapter. Types without an adapter yet fail loudly here.
func NewFromResolved(resolved platform.ResolvedModel) (domain.LLM, error) {
	switch resolved.Type {
	case platform.ModelTypeChat, platform.ModelTypeVision:
		if resolved.APIFormat != platform.APIChatCompletions {
			return nil, fmt.Errorf("llm: role %q: model type %q requires %q, got %q",
				resolved.Role, resolved.Type, platform.APIChatCompletions, resolved.APIFormat)
		}
		return NewOpenAI(OpenAIConfig{
			BaseURL:        resolved.BaseURL,
			APIKey:         resolved.APIKey,
			Model:          resolved.ModelID,
			Timeout:        resolved.Timeout,
			MaxRetries:     resolved.MaxRetries,
			MaxTokensField: resolved.MaxTokensField,
		})
	default:
		return nil, fmt.Errorf("llm: role %q: model type %q has no adapter yet", resolved.Role, resolved.Type)
	}
}
