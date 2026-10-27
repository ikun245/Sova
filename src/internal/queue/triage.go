package queue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"soc/agent/internal/domain"
	"soc/agent/internal/platform"
)

// ChatModels resolves a configured model role to a chat adapter. The registry
// from internal/llm satisfies this without an adapter layer.
type ChatModels interface {
	ForRole(role string) (domain.LLM, platform.ResolvedModel, error)
}

// Verdict labels. Kept as a closed set so a model cannot invent a new class
// that downstream rules do not understand.
const (
	VerdictTruePositive  = "true_positive"
	VerdictFalsePositive = "false_positive"
	VerdictBenign        = "benign"
	VerdictSuspicious    = "suspicious"
	VerdictUnknown       = "unknown"
)

var validVerdicts = map[string]bool{
	VerdictTruePositive:  true,
	VerdictFalsePositive: true,
	VerdictBenign:        true,
	VerdictSuspicious:    true,
	VerdictUnknown:       true,
}

const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

var validSeverities = map[string]bool{
	SeverityCritical: true,
	SeverityHigh:     true,
	SeverityMedium:   true,
	SeverityLow:      true,
	SeverityInfo:     true,
}

// Verdict is the structured triage conclusion. Every field is required by the
// schema because a partially filled verdict cannot be reviewed.
type Verdict struct {
	Verdict         string               `json:"verdict"`
	Severity        string               `json:"severity"`
	Confidence      float64              `json:"confidence"`
	Rationale       string               `json:"rationale"`
	Evidence        []domain.EvidenceRef `json:"evidence"`
	Missing         []string             `json:"missing"`
	Recommendations []Action             `json:"recommendations"`
	Model           string               `json:"model,omitempty"`
}

type Action struct {
	Action     string `json:"action"`
	Risk       string `json:"risk"`
	Reversible bool   `json:"reversible"`
}

// ExecutionResult is what an executor produces for one intent. NeedsReview
// means "the work stopped correctly and a human must decide" — it is not an
// error, and it must not be retried.
type ExecutionResult struct {
	Kind        string
	Verdict     *Verdict
	Summary     string
	Tokens      int
	NeedsReview bool
	ReviewWhy   []string
	Signals     domain.StallSignals
}

// Executor performs one intent. Returning an error means the step genuinely
// failed; returning NeedsReview means it completed but cannot be trusted.
type Executor interface {
	Execute(ctx context.Context, task domain.Task, intent domain.Intent) (ExecutionResult, error)
}

// TriageExecutor asks a chat model to judge one alert. It runs at most
// maxAttempts model calls: the second attempt exists for malformed output, not
// for retrying a genuinely ambiguous alert.
type TriageExecutor struct {
	models          ChatModels
	modelRole       string
	maxAttempts     int
	confidenceFloor float64
}

func NewTriageExecutor(models ChatModels, modelRole string, confidenceFloor float64) *TriageExecutor {
	if strings.TrimSpace(modelRole) == "" {
		modelRole = string(domain.RoleTriage)
	}
	if confidenceFloor <= 0 {
		confidenceFloor = 0.75
	}
	return &TriageExecutor{
		models:          models,
		modelRole:       modelRole,
		maxAttempts:     2,
		confidenceFloor: confidenceFloor,
	}
}

func (e *TriageExecutor) Execute(ctx context.Context, task domain.Task, intent domain.Intent) (ExecutionResult, error) {
	adapter, resolved, err := e.models.ForRole(e.modelRole)
	if err != nil {
		return ExecutionResult{Kind: intent.Kind}, fmt.Errorf("triage: resolve model role %q: %w", e.modelRole, err)
	}

	alert := strings.TrimSpace(string(intent.Payload))
	if alert == "" || alert == "null" {
		alert = "{}"
	}

	maxTokens := resolved.MaxOutputTokens
	if maxTokens <= 0 {
		maxTokens = 1024
	}

	var lastProblem string
	totalTokens := 0
	for attempt := 1; attempt <= e.maxAttempts; attempt++ {
		response, err := adapter.Complete(ctx, domain.CompletionRequest{
			Messages: []domain.Message{
				{Role: "system", Content: triageSystemPrompt()},
				{Role: "user", Content: triageUserPrompt(task, alert, lastProblem)},
			},
			Temperature: 0,
			MaxTokens:   maxTokens,
			JSONSchema:  triageSchema(),
			// No tools: triage must reason over the given alert, not wander.
		})
		if err != nil {
			// A transport failure is a real error: the agent did not get to
			// judge anything.
			return ExecutionResult{Kind: intent.Kind}, fmt.Errorf("triage: model call failed: %w", err)
		}
		totalTokens += response.Usage.InputTokens + response.Usage.OutputTokens

		verdict, problem := parseVerdict(response.Content)
		if problem != "" {
			lastProblem = problem
			continue
		}

		verdict.Model = resolved.ModelID
		return e.classify(intent, verdict, totalTokens), nil
	}

	// Unusable output after every attempt is a quality problem, not a crash.
	// Sending it to a human is cheaper and safer than another retry loop.
	return ExecutionResult{
		Kind:        intent.Kind,
		Tokens:      totalTokens,
		NeedsReview: true,
		ReviewWhy:   []string{"model returned unusable output: " + lastProblem},
		Signals: domain.StallSignals{
			Confidence:      0,
			ConfidenceFloor: e.confidenceFloor,
			MissingEvidence: 2,
		},
	}, nil
}

// classify decides whether the verdict is trustworthy enough to complete
// automatically. This is where the "don't auto-close high severity" rule lives.
func (e *TriageExecutor) classify(intent domain.Intent, verdict *Verdict, tokens int) ExecutionResult {
	result := ExecutionResult{
		Kind:    intent.Kind,
		Verdict: verdict,
		Tokens:  tokens,
		Summary: fmt.Sprintf("%s/%s conf=%.2f", verdict.Verdict, verdict.Severity, verdict.Confidence),
		Signals: domain.StallSignals{
			Confidence:      verdict.Confidence,
			ConfidenceFloor: e.confidenceFloor,
			MissingEvidence: len(verdict.Missing),
		},
	}

	if verdict.Confidence < e.confidenceFloor {
		result.NeedsReview = true
		result.ReviewWhy = append(result.ReviewWhy,
			fmt.Sprintf("confidence %.2f is below the %.2f floor", verdict.Confidence, e.confidenceFloor))
	}
	// High and critical findings are never auto-closed, whatever the confidence.
	if verdict.Severity == SeverityHigh || verdict.Severity == SeverityCritical {
		result.NeedsReview = true
		result.ReviewWhy = append(result.ReviewWhy, "high severity requires human sign-off")
	}
	if verdict.Verdict == VerdictUnknown {
		result.NeedsReview = true
		result.ReviewWhy = append(result.ReviewWhy, "model could not decide")
	}
	return result
}

// parseVerdict validates structure and semantics. Returning a problem string
// (instead of an error) lets the caller retry once before escalating.
func parseVerdict(content string) (*Verdict, string) {
	raw := extractJSONObject(content)
	if raw == "" {
		return nil, "response contained no JSON object"
	}

	var verdict Verdict
	if err := json.Unmarshal([]byte(raw), &verdict); err != nil {
		return nil, "response was not valid JSON"
	}
	if !validVerdicts[verdict.Verdict] {
		return nil, fmt.Sprintf("unknown verdict %q", verdict.Verdict)
	}
	if !validSeverities[verdict.Severity] {
		return nil, fmt.Sprintf("unknown severity %q", verdict.Severity)
	}
	if verdict.Confidence < 0 || verdict.Confidence > 1 {
		return nil, fmt.Sprintf("confidence %.2f is outside [0,1]", verdict.Confidence)
	}
	if strings.TrimSpace(verdict.Rationale) == "" {
		return nil, "rationale is empty"
	}
	// Grounding gate: a verdict without evidence is an opinion, and an opinion
	// cannot be audited. One usable evidence ref is the minimum.
	usable := 0
	for _, evidence := range verdict.Evidence {
		if strings.TrimSpace(evidence.Ref) != "" {
			usable++
		}
	}
	if usable == 0 {
		return nil, "no evidence with a non-empty ref"
	}
	return &verdict, ""
}

// extractJSONObject tolerates a model wrapping JSON in prose or a code fence.
func extractJSONObject(text string) string {
	start := strings.Index(text, "{")
	if start < 0 {
		return ""
	}
	end := strings.LastIndex(text, "}")
	if end <= start {
		return ""
	}
	return text[start : end+1]
}

func triageSchema() json.RawMessage {
	return json.RawMessage(`{
		"type": "object",
		"required": ["verdict", "severity", "confidence", "rationale", "evidence"],
		"properties": {
			"verdict": {"type": "string", "enum": ["true_positive", "false_positive", "benign", "suspicious", "unknown"]},
			"severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
			"confidence": {"type": "number", "minimum": 0, "maximum": 1},
			"rationale": {"type": "string"},
			"evidence": {
				"type": "array",
				"minItems": 1,
				"items": {
					"type": "object",
					"required": ["kind", "ref"],
					"properties": {
						"kind": {"type": "string"},
						"ref": {"type": "string"},
						"quote": {"type": "string"}
					}
				}
			},
			"missing": {"type": "array", "items": {"type": "string"}},
			"recommendations": {
				"type": "array",
				"items": {
					"type": "object",
					"required": ["action"],
					"properties": {
						"action": {"type": "string"},
						"risk": {"type": "string", "enum": ["low", "medium", "high"]},
						"reversible": {"type": "boolean"}
					}
				}
			}
		}
	}`)
}

func triageSystemPrompt() string {
	return `你是防御性安全运营（SOC）的告警研判分析员。你的职责是判断一条告警的真实性与严重程度。

必须遵守：
1. 只依据告警内容判断，不得假设未提供的信息。
2. 每条结论必须给出证据，evidence 中至少一项的 ref 必须指向告警中真实存在的字段路径或引用。
3. 证据不足时，verdict 用 suspicious 或 unknown，并在 missing 中列出还需要什么。
4. 不要编造字段、日志内容或情报结果。
5. 只输出 JSON，不要任何解释文字。

判定口径：
- true_positive：告警描述的行为确实发生且具有恶意意图。
- false_positive：告警触发原因本身是误报（规则缺陷、正常行为被误判）。
- benign：行为属实但属于合法业务或已授权操作。
- suspicious：有可疑迹象但证据不足以定性。
- unknown：信息不足以判断。

处置建议只能是建议，不要执行任何操作。`
}

func triageUserPrompt(task domain.Task, alert, previousProblem string) string {
	var b strings.Builder
	b.WriteString("【告警原文】\n")
	b.WriteString(alert)
	b.WriteString("\n\n")
	if task.CaseID != "" {
		b.WriteString("案例 ID：")
		b.WriteString(task.CaseID)
		b.WriteString("\n")
	}
	if previousProblem != "" {
		b.WriteString("上一次输出不可用（")
		b.WriteString(previousProblem)
		b.WriteString("），请严格按 schema 重新输出 JSON。\n")
	}
	b.WriteString("\n输出研判结论 JSON。")
	return b.String()
}

// errNoVerdict is returned when an executor is asked to run a kind it does not
// handle, so a mis-queued intent fails loudly instead of being silently marked
// complete.
var errNoVerdict = errors.New("executor does not handle this intent kind")
