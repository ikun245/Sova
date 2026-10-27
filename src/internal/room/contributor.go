package room

import (
	"context"
	"fmt"
	"strings"

	"soc/agent/internal/domain"
	"soc/agent/internal/platform"
)

// ModelResolver turns a model-role name into an adapter. The room service
// depends on this narrow interface so it never imports provider packages.
type ModelResolver interface {
	ForRole(role string) (domain.LLM, platform.ResolvedModel, error)
}

// LLMContributor is the production Contributor: one bounded model turn per
// participant, with no tools and no conversation history.
//
// Two deliberate restrictions keep a consultation cheap and safe:
//   - no tools are offered, so an agent cannot start new work mid-consultation
//   - each turn is independent, so context is O(brief) rather than O(transcript)
type LLMContributor struct {
	models ModelResolver
}

func NewLLMContributor(models ModelResolver) *LLMContributor {
	return &LLMContributor{models: models}
}

func (c *LLMContributor) Ask(ctx context.Context, req TurnRequest) (TurnResult, error) {
	modelRole := strings.TrimSpace(req.ModelRole)
	if modelRole == "" {
		// The synthesizer inherits the first participant's role when the
		// caller did not pick one explicitly.
		modelRole = "triage"
	}
	adapter, resolved, err := c.models.ForRole(modelRole)
	if err != nil {
		return TurnResult{}, fmt.Errorf("room: resolve model role %q: %w", modelRole, err)
	}

	maxTokens := req.MaxTokens
	if maxTokens <= 0 {
		maxTokens = 1024
	}
	// Never exceed what the model can actually emit.
	if resolved.MaxOutputTokens > 0 && maxTokens > resolved.MaxOutputTokens {
		maxTokens = resolved.MaxOutputTokens
	}

	response, err := adapter.Complete(ctx, domain.CompletionRequest{
		Messages: []domain.Message{
			{Role: "system", Content: systemPrompt(req)},
			{Role: "user", Content: userPrompt(req)},
		},
		Temperature: 0.2, // stable reasoning beats variety here
		MaxTokens:   maxTokens,
	})
	if err != nil {
		return TurnResult{}, fmt.Errorf("room: agent %q turn failed: %w", req.AgentKey, err)
	}

	return TurnResult{
		AgentKey: req.AgentKey,
		Text:     strings.TrimSpace(response.Content),
		Tokens:   response.Usage.InputTokens + response.Usage.OutputTokens,
	}, nil
}

func systemPrompt(req TurnRequest) string {
	switch req.Role {
	case TurnSynthesizer:
		return "你是安全研判团队的结论汇总者。你的任务是把多位成员的独立意见综合成一个可执行的结论。" +
			"只输出 JSON，不要任何解释文字。字段：outcome（proceed/rework/escalate_human/abandon）、" +
			"rationale（为什么，需引用成员给出的证据）、actions（字符串数组）、" +
			"next_owner（继续工作的 agent key）、evidence（数组，每项含 kind/ref/quote）。" +
			"若成员意见冲突且无法用证据裁决，outcome 必须是 escalate_human。" +
			"禁止编造成员没有提供的证据。"
	default:
		duty := dutyGuidance(req.Duty)
		return "你是安全研判团队的成员，本次只是被召集会诊，不是执行任务。" +
			"你只能基于给出的简报和证据表态，不能调用工具、不能假设未提供的信息。" +
			duty +
			"输出要求：先一句结论，再给理由，最后明确指出还需要什么证据。总长不超过 200 字。"
	}
}

func dutyGuidance(duty string) string {
	switch strings.ToLower(strings.TrimSpace(duty)) {
	case "triage":
		return "你的职责是研判：判断告警真伪、严重程度，以及是否证据不足。"
	case "hunting":
		return "你的职责是狩猎：判断是否存在未发现的关联活动，指出还可以查什么。"
	case "intel":
		return "你的职责是情报：判断 IOC/TTP 是否可信，指出情报是否过期或矛盾。"
	case "critic":
		return "你的职责是质疑：主动指出结论中的漏洞、未经验证的假设和逻辑跳跃。"
	case "reporter":
		return "你的职责是交付：判断当前结论能否写成可复核的报告，还缺哪些证据。"
	default:
		return "你的职责是从你的专业角度给出判断。"
	}
}

func userPrompt(req TurnRequest) string {
	var b strings.Builder

	b.WriteString("【会诊主题】\n")
	b.WriteString(req.Topic)
	b.WriteString("\n\n【问题简报】\n")
	b.WriteString("问题：")
	b.WriteString(req.Brief.Problem)
	b.WriteString("\n")
	if len(req.Brief.Attempts) > 0 {
		b.WriteString("已尝试：\n")
		for _, attempt := range req.Brief.Attempts {
			b.WriteString("- ")
			b.WriteString(attempt)
			b.WriteString("\n")
		}
	}
	if len(req.Brief.Evidence) > 0 {
		b.WriteString("已有证据：\n")
		for _, evidence := range req.Brief.Evidence {
			b.WriteString("- [")
			b.WriteString(evidence.Kind)
			b.WriteString("] ")
			b.WriteString(evidence.Ref)
			if evidence.Quote != "" {
				b.WriteString("：")
				b.WriteString(evidence.Quote)
			}
			b.WriteString("\n")
		}
	}
	if len(req.Brief.Missing) > 0 {
		b.WriteString("缺失信息：\n")
		for _, missing := range req.Brief.Missing {
			b.WriteString("- ")
			b.WriteString(missing)
			b.WriteString("\n")
		}
	}
	if req.Brief.Ask != "" {
		b.WriteString("需要你回答：")
		b.WriteString(req.Brief.Ask)
		b.WriteString("\n")
	}

	if req.Role == TurnSynthesizer {
		b.WriteString("\n【成员意见】\n")
		for _, reply := range req.Replies {
			b.WriteString("--- ")
			b.WriteString(reply.AgentKey)
			b.WriteString(" ---\n")
			b.WriteString(reply.Text)
			b.WriteString("\n")
		}
		b.WriteString("\n现在输出综合结论 JSON。")
	}

	return b.String()
}

// StaticResolver resolves every model role to one adapter. Used in tests and
// for single-model deployments.
type StaticResolver struct {
	Model domain.LLM
	Err   error
}

func (s StaticResolver) ForRole(string) (domain.LLM, platform.ResolvedModel, error) {
	if s.Err != nil {
		return nil, platform.ResolvedModel{}, s.Err
	}
	if s.Model == nil {
		return nil, platform.ResolvedModel{}, fmt.Errorf("room: no model configured")
	}
	return s.Model, platform.ResolvedModel{Role: "triage", Type: platform.ModelTypeChat}, nil
}

// compile-time guard that the production contributor satisfies the port.
var _ Contributor = (*LLMContributor)(nil)
