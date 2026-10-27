package agent

import (
	"strings"
	"testing"

	"soc/agent/internal/domain"
)

func catalog() []SpecCatalogEntry {
	return []SpecCatalogEntry{
		{Name: "dns_lookup", Risk: domain.RiskPassive},
		{Name: "http_probe", Risk: domain.RiskLight},
		{Name: "web_fetch", Risk: domain.RiskLight},
		{Name: "http_request", Risk: domain.RiskLight},
		{Name: "http_intruder", Risk: domain.RiskActive},
		{Name: "port_scan", Risk: domain.RiskActive},
	}
}

func TestRosterHasNoToolsForJudgementDuties(t *testing.T) {
	// Planning, judgement and reporting produce no traffic, so they must not
	// hold a tool: that removes the whole class of "the critic decided to scan".
	roster := Roster()
	for _, duty := range []Duty{DutyPlan, DutyCritic, DutyReport} {
		spec, ok := roster[duty]
		if !ok {
			t.Fatalf("duty %q is missing from the roster", duty)
		}
		if len(spec.Tools) != 0 {
			t.Fatalf("duty %q has tools %v, want none", duty, spec.Tools)
		}
	}
}

func TestRosterCoversEveryDuty(t *testing.T) {
	roster := Roster()
	for _, duty := range []Duty{DutyPlan, DutyRecon, DutyWeb, DutyExploit, DutyCritic, DutyReport} {
		if _, ok := roster[duty]; !ok {
			t.Fatalf("duty %q is missing", duty)
		}
	}
	if len(roster) != 6 {
		t.Fatalf("roster size = %d, want the fixed six", len(roster))
	}
}

func TestRosterEveryDutyHasABudget(t *testing.T) {
	// A duty without a cap is a duty that can run forever.
	for duty, spec := range Roster() {
		if spec.MaxSteps <= 0 {
			t.Fatalf("duty %q has no step cap", duty)
		}
		if spec.MaxTokens <= 0 {
			t.Fatalf("duty %q has no token cap", duty)
		}
		if strings.TrimSpace(spec.SystemPrompt) == "" {
			t.Fatalf("duty %q has no instruction", duty)
		}
		if !strings.HasPrefix(spec.ModelRole, "agent.") {
			t.Fatalf("duty %q model role = %q, want an agent.* role", duty, spec.ModelRole)
		}
	}
}

func TestSpecForFiltersByCeiling(t *testing.T) {
	// Under an active ceiling the active tools survive; under light they do not.
	active, err := SpecFor(DutyWeb, domain.RiskActive, catalog())
	if err != nil {
		t.Fatalf("SpecFor returned error: %v", err)
	}
	if !contains(active.Tools, "http_intruder") {
		t.Fatalf("active tool dropped under an active ceiling: %v", active.Tools)
	}

	light, err := SpecFor(DutyWeb, domain.RiskLight, catalog())
	if err != nil {
		t.Fatalf("SpecFor returned error: %v", err)
	}
	if contains(light.Tools, "http_intruder") {
		t.Fatalf("active tool survived a light ceiling: %v", light.Tools)
	}
	if !contains(light.Tools, "http_request") {
		t.Fatalf("light tool dropped under a light ceiling: %v", light.Tools)
	}
}

func TestSpecForKeepsWhitelistExact(t *testing.T) {
	// A tool the engagement allows but the duty does not declare must stay out:
	// the duty whitelist is narrower than the catalog on purpose.
	spec, err := SpecFor(DutyRecon, domain.RiskActive, catalog())
	if err != nil {
		t.Fatalf("SpecFor returned error: %v", err)
	}
	if contains(spec.Tools, "http_intruder") {
		t.Fatalf("recon must not hold the intruder: %v", spec.Tools)
	}
	if contains(spec.Tools, "http_request") {
		t.Fatalf("recon must not hold the raw repeater: %v", spec.Tools)
	}
}

func TestSpecForPassiveOnlyCeilingLeavesNoActiveTools(t *testing.T) {
	spec, err := SpecFor(DutyRecon, domain.RiskPassive, catalog())
	if err != nil {
		t.Fatalf("SpecFor returned error: %v", err)
	}
	for _, name := range spec.Tools {
		if name != "dns_lookup" {
			t.Fatalf("tool %q survived a passive-only ceiling", name)
		}
	}
}

func TestSpecForRejectsUnknownDuty(t *testing.T) {
	if _, err := SpecFor(Duty("swarm"), domain.RiskActive, catalog()); err == nil {
		t.Fatal("an unknown duty must be rejected rather than defaulted")
	}
}

func TestToolWhitelistRendersSorted(t *testing.T) {
	spec := AgentSpec{Tools: []string{"web_fetch", "http_request"}}
	if got := spec.ToolWhitelist(); got != "http_request,web_fetch" {
		t.Fatalf("ToolWhitelist = %q", got)
	}
	if got := (AgentSpec{}).ToolWhitelist(); got != "(none)" {
		t.Fatalf("empty whitelist = %q", got)
	}
}

func TestSystemPromptNeverAdvertisesUngrantedTools(t *testing.T) {
	scope := domain.TargetScope{Domains: []string{"example.com"}, MaxRisk: domain.RiskLight}
	spec, err := SpecFor(DutyWeb, domain.RiskLight, catalog())
	if err != nil {
		t.Fatalf("SpecFor returned error: %v", err)
	}
	prompt := SystemPrompt(spec, scope, []ToolDoc{
		{Name: "http_request", Risk: domain.RiskLight, Note: "repeater"},
	}, "2026-10-27T00:00:00Z")

	if strings.Contains(prompt, "http_intruder") {
		t.Fatal("the prompt advertised a tool the ceiling filtered out")
	}
	if !strings.Contains(prompt, "http_request") {
		t.Fatal("the prompt omitted a granted tool")
	}
	if !strings.Contains(prompt, "example.com") {
		t.Fatal("the prompt omitted the authorized domain")
	}
}

func TestSystemPromptStatesCodeEnforcedRules(t *testing.T) {
	// These sentences exist because the same rules are enforced in exec.Runner.
	// Removing them from the prompt would not weaken security, but it would make
	// the model waste steps discovering the wall.
	prompt := SystemPrompt(AgentSpec{Duty: DutyRecon}, domain.TargetScope{}, nil, "")
	for _, want := range []string{"授权范围", "intrusive", "approval"} {
		if !strings.Contains(prompt, want) {
			t.Fatalf("prompt is missing %q", want)
		}
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
