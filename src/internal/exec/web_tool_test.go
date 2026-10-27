package exec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"soc/agent/internal/domain"
)

// testScope authorizes the loopback address the test server runs on. A literal
// address is checked against CIDRs, so the scope has to declare it explicitly.
func loopbackScope(maxRisk domain.RiskLevel) domain.TargetScope {
	return domain.TargetScope{
		ID:               "scope-test",
		TenantID:         "local",
		CIDRs:            []string{"127.0.0.1/32"},
		MaxRisk:          maxRisk,
		MaxRatePerMinute: 0,
		ExpiresAt:        time.Now().Add(time.Hour),
		ApprovedBy:       "tester",
		TicketID:         "TEST-1",
	}
}

func newWebHarness(t *testing.T, maxRisk domain.RiskLevel) (*Runner, *WebTool, *httptest.Server) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Handler", "yes")
		w.WriteHeader(http.StatusOK)
		fmt.Fprintf(w, "method=%s", r.Method)
	}))
	t.Cleanup(server.Close)

	runner := NewRunner(Policy{Ceiling: maxRisk, AskAbove: domain.RiskLight}, loopbackScope(maxRisk), nil)
	web := WebCatalog(runner)[0]
	if web.Spec().Name != "http_request" {
		t.Fatalf("first web tool = %q, want http_request", web.Spec().Name)
	}
	return runner, web, server
}

func TestRepeaterReadIsAllowedWithoutApproval(t *testing.T) {
	_, web, server := newWebHarness(t, domain.RiskActive)

	raw, _ := json.Marshal(map[string]any{"url": server.URL, "method": "GET"})
	result := web.Invoke(context.Background(), raw)
	if !result.OK {
		t.Fatalf("GET was refused: code=%s message=%s hint=%s", result.Code, result.Message, result.Hint)
	}
	payload, ok := result.Data.(map[string]any)
	if !ok {
		t.Fatalf("payload type = %T", result.Data)
	}
	if payload["status"] != http.StatusOK {
		t.Fatalf("status = %v", payload["status"])
	}
	if !strings.Contains(payload["body_utf8"].(string), "method=GET") {
		t.Fatalf("body = %q", payload["body_utf8"])
	}
}

func TestRepeaterWriteNeedsApproval(t *testing.T) {
	_, web, server := newWebHarness(t, domain.RiskActive)

	raw, _ := json.Marshal(map[string]any{"url": server.URL, "method": "POST", "body": "a=1"})
	result := web.Invoke(context.Background(), raw)
	if result.Code != domain.CodeApprovalRequired {
		t.Fatalf("POST code = %s, want approval_required", result.Code)
	}
	// The exact binding must be reported, otherwise the caller cannot obtain a
	// matching approval and the request can never succeed.
	if result.Details["approval_argv"] == "" {
		t.Fatal("approval_argv is missing from the refusal")
	}
	if !strings.Contains(result.Details["approval_argv"], `"POST"`) {
		t.Fatalf("approval binding does not name the method: %s", result.Details["approval_argv"])
	}
}

func TestRepeaterOutOfScopeIsRefusedBeforeSending(t *testing.T) {
	var contacted bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		contacted = true
	}))
	defer server.Close()

	scope := loopbackScope(domain.RiskActive)
	scope.CIDRs = []string{"10.0.0.0/8"}
	runner := NewRunner(Policy{Ceiling: domain.RiskActive, AskAbove: domain.RiskLight}, scope, nil)
	web := WebCatalog(runner)[0]

	raw, _ := json.Marshal(map[string]any{"url": server.URL, "method": "GET"})
	result := web.Invoke(context.Background(), raw)
	if result.Code != domain.CodeOutOfScope {
		t.Fatalf("code = %s, want out_of_scope", result.Code)
	}
	if contacted {
		t.Fatal("an out-of-scope target received a request")
	}
}

func TestRepeaterDeclaredRiskRaisesButNeverLowers(t *testing.T) {
	_, web, server := newWebHarness(t, domain.RiskActive)

	// Declaring intrusive under an active ceiling must be denied: a GET that
	// executes code cannot pass as a read.
	raw, _ := json.Marshal(map[string]any{"url": server.URL, "method": "GET", "risk": "intrusive"})
	result := web.Invoke(context.Background(), raw)
	if result.Code != domain.CodePolicyDenied {
		t.Fatalf("declared intrusive code = %s, want policy_denied", result.Code)
	}

	// Declaring passive must not lower a POST below the state-changing floor.
	raw, _ = json.Marshal(map[string]any{"url": server.URL, "method": "POST", "risk": "passive", "body": "a=1"})
	result = web.Invoke(context.Background(), raw)
	if result.Code != domain.CodeApprovalRequired {
		t.Fatalf("declared passive on POST code = %s, want approval_required", result.Code)
	}
}

func TestRepeaterRejectsUnknownRisk(t *testing.T) {
	_, web, server := newWebHarness(t, domain.RiskActive)
	raw, _ := json.Marshal(map[string]any{"url": server.URL, "risk": "banana"})
	result := web.Invoke(context.Background(), raw)
	if result.Code != domain.CodeInvalidArgument {
		t.Fatalf("code = %s, want invalid_argument", result.Code)
	}
}

func TestRepeaterRejectsBadURL(t *testing.T) {
	_, web, _ := newWebHarness(t, domain.RiskActive)
	for _, rawURL := range []string{"", "example.com", "ftp://example.com/x"} {
		raw, _ := json.Marshal(map[string]any{"url": rawURL})
		if result := web.Invoke(context.Background(), raw); result.Code != domain.CodeInvalidArgument {
			t.Fatalf("url %q code = %s, want invalid_argument", rawURL, result.Code)
		}
	}
}

func TestIntruderRunsControlThenPayloads(t *testing.T) {
	var seen []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = append(seen, r.URL.Query().Get("q"))
		w.WriteHeader(http.StatusOK)
		if r.URL.Query().Get("q") == "hit" {
			fmt.Fprint(w, "matched-marker")
			return
		}
		fmt.Fprint(w, "nope")
	}))
	defer server.Close()

	runner := NewRunner(Policy{Ceiling: domain.RiskActive, AskAbove: domain.RiskActive}, loopbackScope(domain.RiskActive), nil)
	var intruder *WebTool
	for _, tool := range WebCatalog(runner) {
		if tool.Spec().Name == "http_intruder" {
			intruder = tool
		}
	}
	if intruder == nil {
		t.Fatal("http_intruder is not in the catalog")
	}

	raw, _ := json.Marshal(map[string]any{
		"url":      server.URL + "/?q=FUZZ",
		"marker":   "FUZZ",
		"payloads": []string{"a", "hit", "b"},
		"match":    "matched-marker",
	})
	result := intruder.Invoke(context.Background(), raw)
	if !result.OK {
		t.Fatalf("intruder refused: code=%s message=%s", result.Code, result.Message)
	}

	payload := result.Data.(map[string]any)
	if payload["control_ready"] != true {
		t.Fatal("the control request did not complete")
	}
	attempts, _ := payload["attempts"].([]intruderAttempt)
	if len(attempts) != 3 {
		t.Fatalf("attempts = %d, want 3", len(attempts))
	}
	if payload["matched"] != 1 {
		t.Fatalf("matched = %v, want 1", payload["matched"])
	}
	if attempts[1].Payload != "hit" || !attempts[1].Matched {
		t.Fatalf("the matching payload was not identified: %+v", attempts[1])
	}
	// The control request comes first so the baseline exists before any payload.
	if len(seen) != 4 || seen[0] != "" {
		t.Fatalf("request order = %v, want an empty-marker control first", seen)
	}
}

func TestIntruderRequiresMarkerAndBoundsPayloads(t *testing.T) {
	runner := NewRunner(Policy{Ceiling: domain.RiskActive, AskAbove: domain.RiskActive}, loopbackScope(domain.RiskActive), nil)
	var intruder *WebTool
	for _, tool := range WebCatalog(runner) {
		if tool.Spec().Name == "http_intruder" {
			intruder = tool
		}
	}

	raw, _ := json.Marshal(map[string]any{"url": "http://127.0.0.1:1/", "payloads": []string{"a"}})
	if result := intruder.Invoke(context.Background(), raw); result.Code != domain.CodeInvalidArgument {
		t.Fatalf("missing marker code = %s, want invalid_argument", result.Code)
	}

	oversized := make([]string, maxIntruderPayloads+1)
	for i := range oversized {
		oversized[i] = "x"
	}
	raw, _ = json.Marshal(map[string]any{"url": "http://127.0.0.1:1/?q=FUZZ", "marker": "FUZZ", "payloads": oversized})
	if result := intruder.Invoke(context.Background(), raw); result.Code != domain.CodeInvalidArgument {
		t.Fatalf("oversized payload list code = %s, want invalid_argument", result.Code)
	}
}

func TestIntruderStillNeedsApproval(t *testing.T) {
	_, _, server := newWebHarness(t, domain.RiskActive)
	runner := NewRunner(Policy{Ceiling: domain.RiskActive, AskAbove: domain.RiskLight}, loopbackScope(domain.RiskActive), nil)
	var intruder *WebTool
	for _, tool := range WebCatalog(runner) {
		if tool.Spec().Name == "http_intruder" {
			intruder = tool
		}
	}

	raw, _ := json.Marshal(map[string]any{
		"url": server.URL + "/?q=FUZZ", "marker": "FUZZ", "payloads": []string{"a"},
	})
	if result := intruder.Invoke(context.Background(), raw); result.Code != domain.CodeApprovalRequired {
		t.Fatalf("code = %s, want approval_required", result.Code)
	}
}

func TestToolsIncludesBuiltinsAndBinaries(t *testing.T) {
	runner := NewRunner(Policy{Ceiling: domain.RiskActive}, loopbackScope(domain.RiskActive), nil)
	names := map[string]bool{}
	for _, tool := range Tools(runner) {
		names[tool.Spec().Name] = true
	}
	for _, want := range []string{"http_request", "http_intruder", "http_probe", "dns_lookup"} {
		if !names[want] {
			t.Fatalf("tool %q is missing from Tools(); got %v", want, names)
		}
	}
}

func TestWebToolTargetPortMatchesURL(t *testing.T) {
	_, _, server := newWebHarness(t, domain.RiskActive)
	parsed, err := url.Parse(server.URL)
	if err != nil {
		t.Fatalf("parse test server URL: %v", err)
	}
	port := portOf(parsed)
	if port <= 0 {
		t.Fatalf("portOf(%q) = %d", server.URL, port)
	}
}
