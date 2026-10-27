package exec

import (
	"context"
	"testing"
	"time"

	"soc/agent/internal/domain"
)

func TestEscalationRaisesRiskForDangerousFlags(t *testing.T) {
	// Same binary, same nominal level: only the flags differ.
	policy := Policy{Ceiling: domain.RiskIntrusive, AskAbove: domain.RiskIntrusive}

	cases := []struct {
		name string
		argv []string
		want domain.RiskLevel
	}{
		{"sqlmap banner only reads", []string{"sqlmap", "-u", "https://example.com/?id=1", "--banner"}, domain.RiskIntrusive},
		{"sqlmap os-shell is RCE", []string{"sqlmap", "-u", "x", "--os-shell"}, domain.RiskIntrusive},
		{"sqlmap file-read", []string{"sqlmap", "-u", "x", "--file-read=/etc/passwd"}, domain.RiskIntrusive},
		{"sqlmap dump", []string{"sqlmap", "-u", "x", "--dump-all"}, domain.RiskIntrusive},
		{"nmap vuln scripts", []string{"nmap", "--script", "vuln", "example.com"}, domain.RiskIntrusive},
		{"nmap service scan", []string{"nmap", "-sV", "example.com"}, domain.RiskActive},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := policy.Classify(tc.argv)
			if got.Risk != tc.want {
				t.Fatalf("risk = %q, want %q (reason: %s)", got.Risk, tc.want, got.Reason)
			}
		})
	}
}

func TestEscalatedCommandIsDeniedUnderActiveCeiling(t *testing.T) {
	// An engagement that permits active work must still refuse --os-shell.
	policy := Policy{Ceiling: domain.RiskActive, AskAbove: domain.RiskActive}

	got := policy.Classify([]string{"sqlmap", "-u", "https://example.com/?id=1", "--os-shell"})
	if got.Decision != DecisionDeny {
		t.Fatalf("decision = %q, want deny; flag escalation must not be bypassed by a permissive ceiling", got.Decision)
	}
	if got.Reason == "" {
		t.Fatal("the denial must explain that the flags raised the risk")
	}
}

func TestEscalationNeverLowersRisk(t *testing.T) {
	// A curl with a POST body becomes active, but a passive tool with odd
	// arguments must not drop below its baseline.
	policy := Policy{Ceiling: domain.RiskActive, AskAbove: domain.RiskActive}

	got := policy.Classify([]string{"curl", "-X", "POST", "https://example.com/"})
	if got.Risk != domain.RiskActive {
		t.Fatalf("risk = %q, want active for a state-changing request", got.Risk)
	}
	// Passive tools have no escalation rules, so they stay passive.
	if r := policy.Classify([]string{"dig", "+short", "example.com"}); r.Risk != domain.RiskPassive {
		t.Fatalf("dig risk = %q, want passive", r.Risk)
	}
}

func TestRateLimiterSpacesRequests(t *testing.T) {
	limiter := NewRateLimiter(60) // one per second
	if limiter == nil {
		t.Fatal("a positive rate must produce a limiter")
	}
	if limiter.Interval() != time.Second {
		t.Fatalf("interval = %v, want 1s", limiter.Interval())
	}

	var waits []time.Duration
	fake := time.Now()
	limiter.now = func() time.Time { return fake }
	limiter.sleep = func(_ context.Context, d time.Duration) error {
		waits = append(waits, d)
		fake = fake.Add(d) // advance virtual time so the next slot is correct
		return nil
	}

	for i := 0; i < 3; i++ {
		if err := limiter.Wait(context.Background()); err != nil {
			t.Fatalf("Wait() error = %v", err)
		}
	}

	// First call fits the current slot; the next two must each wait an interval.
	if len(waits) != 2 {
		t.Fatalf("waits = %v, want 2 delays for 3 requests", waits)
	}
	for _, d := range waits {
		if d != time.Second {
			t.Fatalf("delay = %v, want the 1s interval", d)
		}
	}
}

func TestRateLimiterIsNilForUnlimited(t *testing.T) {
	if NewRateLimiter(0) != nil {
		t.Fatal("rate 0 must mean unlimited, not a zero-interval limiter")
	}
	if NewRateLimiter(-1) != nil {
		t.Fatal("a negative rate must be treated as unlimited")
	}
	var limiter *RateLimiter
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatalf("a nil limiter must be a no-op: %v", err)
	}
}

func TestRateLimiterHonoursCancellation(t *testing.T) {
	limiter := NewRateLimiter(6) // one every 10s
	fake := time.Now()
	limiter.now = func() time.Time { return fake }

	// Consume the first slot, then cancel during the second wait.
	if err := limiter.Wait(context.Background()); err != nil {
		t.Fatalf("first Wait() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := limiter.Wait(ctx); err == nil {
		t.Fatal("a cancelled wait must return the context error")
	}
}

func TestRunnerAppliesScopeRate(t *testing.T) {
	scope := testScope()
	scope.MaxRatePerMinute = 120 // one per 500ms
	runner := NewRunner(Policy{Ceiling: domain.RiskActive, AskAbove: domain.RiskActive}, scope, nil)
	if runner.Limiter == nil {
		t.Fatal("the runner must build a limiter from the scope's rate")
	}
	if runner.Limiter.Interval() != 500*time.Millisecond {
		t.Fatalf("interval = %v, want 500ms", runner.Limiter.Interval())
	}
}
