package queue

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"soc/agent/internal/domain"
	"soc/agent/internal/llm"
	"soc/agent/internal/platform"
)

func triageModels(t *testing.T, model domain.LLM) ChatModels {
	t.Helper()
	return fakeChatModels{model: model, resolved: platform.ResolvedModel{
		Role: "triage", Type: platform.ModelTypeChat, ModelID: "mock-model", MaxOutputTokens: 800,
	}}
}

type fakeChatModels struct {
	model    domain.LLM
	resolved platform.ResolvedModel
	err      error
	roles    []string
}

func (f fakeChatModels) ForRole(role string) (domain.LLM, platform.ResolvedModel, error) {
	if f.err != nil {
		return nil, platform.ResolvedModel{}, f.err
	}
	return f.model, f.resolved, nil
}

func (f *fakeChatModels) ForRoleRecorder(role string) (domain.LLM, platform.ResolvedModel, error) {
	f.roles = append(f.roles, role)
	return f.model, f.resolved, nil
}

const validVerdictJSON = `{
  "verdict":"true_positive",
  "severity":"high",
  "confidence":0.88,
  "rationale":"encoded powershell with outbound connection",
  "evidence":[{"kind":"alert_field","ref":"process.command_line","quote":"powershell -enc"}],
  "missing":[],
  "recommendations":[{"action":"isolate_host","risk":"medium","reversible":true}]
}`

func newTriageIntent(payload string) domain.Intent {
	return domain.Intent{
		ID:      "intent-1",
		TaskID:  "task-1",
		Seq:     1,
		Kind:    "triage",
		Payload: json.RawMessage(payload),
		Status:  domain.IntentStatusClaimed,
	}
}

func TestTriageExecutorReturnsValidatedVerdict(t *testing.T) {
	model := llm.NewFake("mock-model")
	model.Queue(domain.CompletionResponse{
		Content: validVerdictJSON,
		Usage:   domain.Usage{InputTokens: 300, OutputTokens: 100},
	})
	executor := NewTriageExecutor(triageModels(t, model), "triage", 0.75)

	result, err := executor.Execute(context.Background(),
		domain.Task{ID: "task-1"}, newTriageIntent(`{"event":"blocked"}`))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Verdict == nil {
		t.Fatal("expected a parsed verdict")
	}
	if result.Verdict.Verdict != VerdictTruePositive {
		t.Fatalf("Verdict = %q", result.Verdict.Verdict)
	}
	if result.Verdict.Model != "mock-model" {
		t.Fatalf("Model = %q, want the resolved model id for attribution", result.Verdict.Model)
	}
	if result.Tokens != 400 {
		t.Fatalf("Tokens = %d, want 400", result.Tokens)
	}
	// High severity always needs a human, even at high confidence.
	if !result.NeedsReview {
		t.Fatal("high severity must require review regardless of confidence")
	}
}

func TestTriageExecutorRequiresReviewForLowConfidence(t *testing.T) {
	model := llm.NewFake("m")
	model.Queue(domain.CompletionResponse{Content: `{
		"verdict":"suspicious","severity":"low","confidence":0.4,
		"rationale":"unclear","evidence":[{"kind":"alert_field","ref":"a.b"}]
	}`})
	executor := NewTriageExecutor(triageModels(t, model), "triage", 0.75)

	result, err := executor.Execute(context.Background(), domain.Task{}, newTriageIntent(`{}`))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !result.NeedsReview {
		t.Fatal("confidence below the floor must require review")
	}
	if result.Signals.Confidence != 0.4 {
		t.Fatalf("Signals.Confidence = %v, want the parsed confidence", result.Signals.Confidence)
	}
}

func TestTriageExecutorAutoClosesClearLowSeverityNoise(t *testing.T) {
	model := llm.NewFake("m")
	model.Queue(domain.CompletionResponse{Content: `{
		"verdict":"false_positive","severity":"low","confidence":0.95,
		"rationale":"known scanner","evidence":[{"kind":"alert_field","ref":"user_agent","quote":"nessus"}]
	}`})
	executor := NewTriageExecutor(triageModels(t, model), "triage", 0.75)

	result, err := executor.Execute(context.Background(), domain.Task{}, newTriageIntent(`{}`))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.NeedsReview {
		t.Fatalf("a confident low-severity false positive should not need review: %v", result.ReviewWhy)
	}
}

func TestTriageExecutorRetriesMalformedOutputOnce(t *testing.T) {
	model := llm.NewFake("m")
	model.Queue(domain.CompletionResponse{Content: "I think it is probably bad."})
	model.Queue(domain.CompletionResponse{Content: validVerdictJSON})
	executor := NewTriageExecutor(triageModels(t, model), "triage", 0.75)

	result, err := executor.Execute(context.Background(), domain.Task{}, newTriageIntent(`{}`))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if result.Verdict == nil {
		t.Fatal("the second attempt should have produced a verdict")
	}
	if len(model.Requests()) != 2 {
		t.Fatalf("model calls = %d, want 2", len(model.Requests()))
	}
	// The retry must tell the model what was wrong.
	second := model.Requests()[1].Messages[1].Content
	if !strings.Contains(second, "上一次输出不可用") {
		t.Fatal("the retry prompt should explain that the previous output was unusable")
	}
}

func TestTriageExecutorSendsNoToolsAndUsesZeroTemperature(t *testing.T) {
	model := llm.NewFake("m")
	model.Queue(domain.CompletionResponse{Content: validVerdictJSON})
	executor := NewTriageExecutor(triageModels(t, model), "triage", 0.75)

	if _, err := executor.Execute(context.Background(), domain.Task{}, newTriageIntent(`{}`)); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	request := model.Requests()[0]
	if len(request.Tools) != 0 {
		t.Fatal("triage must not offer tools; verdicts are judged from the alert, not by acting")
	}
	if request.Temperature != 0 {
		t.Fatalf("Temperature = %v, want 0 for deterministic judgement", request.Temperature)
	}
	if len(request.JSONSchema) == 0 {
		t.Fatal("triage should request structured output")
	}
	if request.MaxTokens != 800 {
		t.Fatalf("MaxTokens = %d, want the model's declared output limit", request.MaxTokens)
	}
}

func TestTriageExecutorEscalatesWhenOutputNeverValid(t *testing.T) {
	model := llm.NewFake("m")
	model.Queue(domain.CompletionResponse{Content: "nope"})
	model.Queue(domain.CompletionResponse{Content: "still nope"})
	executor := NewTriageExecutor(triageModels(t, model), "triage", 0.75)

	result, err := executor.Execute(context.Background(), domain.Task{}, newTriageIntent(`{}`))
	if err != nil {
		t.Fatalf("unusable output is a quality problem, not an execution error: %v", err)
	}
	if !result.NeedsReview {
		t.Fatal("unusable output after retries must go to a human")
	}
	if len(result.ReviewWhy) == 0 {
		t.Fatal("ReviewWhy must explain why review is required")
	}
}

func TestTriageExecutorFailsOnTransportError(t *testing.T) {
	model := llm.NewFake("m")
	model.QueueError(errors.New("upstream 503"))
	executor := NewTriageExecutor(triageModels(t, model), "triage", 0.75)

	if _, err := executor.Execute(context.Background(), domain.Task{}, newTriageIntent(`{}`)); err == nil {
		t.Fatal("a transport failure must be an error so consultation can be triggered")
	}
}

func TestTriageExecutorRejectsVerdictWithoutEvidence(t *testing.T) {
	model := llm.NewFake("m")
	// Ungrounded verdicts are the main hallucination risk; both attempts must
	// be rejected and the alert sent to a human.
	model.Queue(domain.CompletionResponse{Content: `{
		"verdict":"true_positive","severity":"low","confidence":0.99,
		"rationale":"looks bad","evidence":[]
	}`})
	model.Queue(domain.CompletionResponse{Content: `{
		"verdict":"true_positive","severity":"low","confidence":0.99,
		"rationale":"looks bad","evidence":[{"kind":"alert_field","ref":"  "}]
	}`})
	executor := NewTriageExecutor(triageModels(t, model), "triage", 0.75)

	result, err := executor.Execute(context.Background(), domain.Task{}, newTriageIntent(`{}`))
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if !result.NeedsReview {
		t.Fatal("a verdict without usable evidence must never be auto-accepted")
	}
}

func TestParseVerdictRejectsInvalidEnums(t *testing.T) {
	cases := map[string]string{
		"unknown verdict":  `{"verdict":"malware","severity":"high","confidence":0.9,"rationale":"x","evidence":[{"kind":"a","ref":"b"}]}`,
		"unknown severity": `{"verdict":"true_positive","severity":"urgent","confidence":0.9,"rationale":"x","evidence":[{"kind":"a","ref":"b"}]}`,
		"bad confidence":   `{"verdict":"true_positive","severity":"high","confidence":1.4,"rationale":"x","evidence":[{"kind":"a","ref":"b"}]}`,
		"empty rationale":  `{"verdict":"true_positive","severity":"high","confidence":0.9,"rationale":"  ","evidence":[{"kind":"a","ref":"b"}]}`,
	}
	for name, content := range cases {
		t.Run(name, func(t *testing.T) {
			if _, problem := parseVerdict(content); problem == "" {
				t.Fatal("expected the verdict to be rejected")
			}
		})
	}
}

func TestParseVerdictToleratesFencedJSON(t *testing.T) {
	content := "```json\n" + validVerdictJSON + "\n```"
	verdict, problem := parseVerdict(content)
	if problem != "" {
		t.Fatalf("problem = %q, want fenced JSON to be accepted", problem)
	}
	if verdict.Verdict != VerdictTruePositive {
		t.Fatalf("Verdict = %q", verdict.Verdict)
	}
}
