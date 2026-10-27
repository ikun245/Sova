package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"strings"
	"time"

	"soc/agent/internal/domain"
	"soc/agent/internal/llm"
	"soc/agent/internal/platform"
)

// runModels validates the models configuration. Checking is free; --ping makes
// one minimal call per role, so it must stay opt-in to avoid spending quota.
func runModels(args []string) error {
	if len(args) == 0 || args[0] != "check" {
		return errors.New("usage: soc models check [--ping]")
	}
	ping := false
	for _, arg := range args[1:] {
		switch arg {
		case "--ping":
			ping = true
		default:
			return fmt.Errorf("unknown flag %q; usage: soc models check [--ping]", arg)
		}
	}

	config, err := platform.LoadModelsConfig()
	if errors.Is(err, platform.ErrModelsNotConfigured) {
		return errors.New("no models configured: set SOC_MODELS_CONFIG to a models YAML file")
	}
	if err != nil {
		return err
	}

	roles := make([]string, 0, len(config.Roles))
	for role := range config.Roles {
		roles = append(roles, role)
	}
	sort.Strings(roles)
	if len(roles) == 0 {
		return errors.New("models config defines no roles")
	}

	var failures []string
	for _, role := range roles {
		resolved, err := config.Resolve(role)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", role, err))
			fmt.Fprintf(os.Stderr, "role %-10s ERROR %v\n", role, err)
			continue
		}

		client, err := llm.NewFromResolved(resolved)
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", role, err))
			fmt.Fprintf(os.Stderr, "role %-10s ERROR %v\n", role, err)
			continue
		}

		fmt.Printf("role %-10s type=%-9s provider=%-12s model=%-24s timeout=%s capabilities=%s\n",
			role, resolved.Type, resolved.ProviderID, resolved.ModelID, resolved.Timeout, formatCapabilities(resolved.Capabilities))
		if resolved.Type == platform.ModelTypeEmbedding {
			fmt.Printf("           dimension=%d\n", resolved.Dimension)
		}
		if resolved.Cost != nil {
			fmt.Printf("           cost_in=%.4f cost_out=%.4f per_million=%s\n",
				resolved.Cost.Input, resolved.Cost.Output, defaultCurrency(resolved.Cost.Currency))
		}

		if !ping {
			continue
		}
		started := time.Now()
		ctx, cancel := context.WithTimeout(context.Background(), resolved.Timeout)
		response, err := client.Complete(ctx, domain.CompletionRequest{
			Messages:  []domain.Message{{Role: "user", Content: "Reply with the single word: ok"}},
			MaxTokens: 16,
		})
		cancel()
		if err != nil {
			failures = append(failures, fmt.Sprintf("%s: ping failed: %v", role, err))
			fmt.Fprintf(os.Stderr, "role %-10s PING FAILED %v\n", role, err)
			continue
		}
		slog.Info("model ping succeeded", "role", role, "latency_ms", time.Since(started).Milliseconds(),
			"input_tokens", response.Usage.InputTokens, "output_tokens", response.Usage.OutputTokens)
		fmt.Printf("           ping ok in %s (in=%d out=%d)\n",
			time.Since(started).Round(time.Millisecond), response.Usage.InputTokens, response.Usage.OutputTokens)
	}

	if len(failures) > 0 {
		return fmt.Errorf("%d model configuration problem(s): %s", len(failures), strings.Join(failures, "; "))
	}
	return nil
}

func formatCapabilities(capabilities []string) string {
	if len(capabilities) == 0 {
		return "none"
	}
	return strings.Join(capabilities, ",")
}

func defaultCurrency(currency string) string {
	if strings.TrimSpace(currency) == "" {
		return "USD"
	}
	return currency
}
