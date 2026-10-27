package llm

import (
	"fmt"
	"strings"
	"sync"

	"soc/agent/internal/domain"
	"soc/agent/internal/platform"
)

// Registry resolves business roles to LLM adapters and caches one adapter per
// model profile. Caching matters for more than speed: several roles commonly
// share a profile, and a shared adapter means one HTTP client, one timeout
// policy, and one place to add rate limiting later.
type Registry struct {
	mu        sync.Mutex
	config    platform.ModelsConfig
	byProfile map[string]domain.LLM
}

func NewRegistry(config platform.ModelsConfig) *Registry {
	return &Registry{config: config, byProfile: map[string]domain.LLM{}}
}

// ForRole resolves a role through profile -> provider and returns its cached
// adapter. The role might come from configuration (triage) or from a team
// member's model_role, so it is validated at runtime rather than at startup.
func (r *Registry) ForRole(role string) (domain.LLM, platform.ResolvedModel, error) {
	role = strings.TrimSpace(role)
	if role == "" {
		return nil, platform.ResolvedModel{}, fmt.Errorf("llm: empty model role")
	}

	resolved, err := r.config.Resolve(role)
	if err != nil {
		return nil, platform.ResolvedModel{}, err
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	if existing, ok := r.byProfile[resolved.ProviderID+"/"+resolved.ModelID]; ok {
		return existing, resolved, nil
	}

	adapter, err := NewFromResolved(resolved)
	if err != nil {
		return nil, platform.ResolvedModel{}, err
	}
	r.byProfile[resolved.ProviderID+"/"+resolved.ModelID] = adapter
	return adapter, resolved, nil
}

// Roles returns the configured role names, so callers can report which roles
// exist without exposing profile details.
func (r *Registry) Roles() []string {
	roles := make([]string, 0, len(r.config.Roles))
	for role := range r.config.Roles {
		roles = append(roles, role)
	}
	return roles
}

// Profile reports a role's resolved model metadata for logging and cost
// attribution, without building an adapter.
func (r *Registry) Profile(role string) (platform.ResolvedModel, error) {
	return r.config.Resolve(role)
}
