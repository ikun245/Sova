package agent

import (
	"fmt"
	"strings"

	"soc/agent/internal/domain"
)

// ToolDoc is a tool as the prompt presents it: name, risk, and the one-line
// purpose. The schema is sent separately as a tool definition, so duplicating
// it here would only invite drift.
type ToolDoc struct {
	Name string
	Risk domain.RiskLevel
	Note string
}

// SystemPrompt assembles the full instruction for one duty from the same scope
// the executor enforces. Two rules:
//
//  1. It never advertises a capability the code would refuse. The tool list is
//     the post-ceiling whitelist, not the catalog.
//  2. It never contains the only copy of a rule. Every constraint stated here
//     is also enforced in exec.Runner, because page content and tool output are
//     attacker-controlled text that can attempt prompt injection.
func SystemPrompt(spec AgentSpec, scope domain.TargetScope, tools []ToolDoc, now string) string {
	var b strings.Builder

	b.WriteString("你是红队团队成员，当前职责：**" + string(spec.Duty) + "**。\n\n")
	b.WriteString(spec.SystemPrompt)
	b.WriteString("\n\n")

	writeScopeSection(&b, ScopeBrief{
		Scope:        scope,
		Ceiling:      scope.MaxRisk,
		AskAbove:     domain.RiskLight,
		AllowedTools: nil,
		Now:          now,
	})
	writeWhitelistSection(&b, spec, tools)
	writeEnvelopeSection(&b)
	writeHardRulesSection(&b)
	writeStopSection(&b)

	return b.String()
}

func writeWhitelistSection(b *strings.Builder, spec AgentSpec, tools []ToolDoc) {
	b.WriteString("## 你当前能调用的工具\n\n")
	if len(tools) == 0 {
		b.WriteString("（你没有工具。不要假设任何探测已经完成，也不要编造输出。）\n\n")
		return
	}
	for _, tool := range tools {
		fmt.Fprintf(b, "- `%s`（%s）：%s\n", tool.Name, tool.Risk, tool.Note)
	}
	b.WriteString("\n不在这个列表里的工具调用会被直接拒绝。需要新工具时说明需求，不要换写法硬试。\n\n")
}

func writeEnvelopeSection(b *strings.Builder) {
	b.WriteString("## 工具返回格式\n\n")
	b.WriteString("每次调用的返回都是同一个信封，成功和失败结构一致：\n\n")
	b.WriteString("```json\n{\"ok\":true,\"code\":\"ok\",\"data\":{...},\"meta\":{\"risk\":\"light\",\"duration_ms\":287}}\n```\n\n")
	b.WriteString("失败时 `ok=false`，请按 `code` 决定下一步，不要只看 `message`：\n\n")
	b.WriteString("| code | 含义 | 你的动作 |\n|---|---|---|\n")
	b.WriteString("| `invalid_argument` | 参数不对 | 修正参数，不要原样重发 |\n")
	b.WriteString("| `out_of_scope` | 目标不在授权内 | **不要重试**，记录后换目标 |\n")
	b.WriteString("| `policy_denied` | 策略拒绝（含风险超限） | **不要换写法绕过**，说明需求 |\n")
	b.WriteString("| `approval_required` | 需要人工审批 | 循环会停下等人；不要改参数反复试 |\n")
	b.WriteString("| `binary_missing` | 工具未安装 | 告知操作员，不要冒充 |\n")
	b.WriteString("| `timeout` | 超时 | 缩小范围后重试一次 |\n")
	b.WriteString("| `command_failed` | 命令非零退出 | 读 stdout/stderr 再调整 |\n\n")
}

func writeHardRulesSection(b *strings.Builder) {
	b.WriteString("## 硬性规则（违反会被代码拒绝）\n\n")
	b.WriteString("- 目标必须在授权范围内；范围外目标即使可达也不探测。\n")
	b.WriteString("- 一次审批只授权一个精确动作；改参数就是另一个动作，会重新审批。\n")
	b.WriteString("- 风险等级只能上调不能下调：执行代码的 GET 必须声明为 `intrusive`。\n")
	b.WriteString("- 不夸大：版本匹配不算可利用，没有回显证据不算执行成功。\n\n")
}

func writeStopSection(b *strings.Builder) {
	b.WriteString("## 何时停止\n\n")
	b.WriteString("达到目标就立刻给出结论，不要继续扩大战果。\n")
	b.WriteString("连续两次同类失败要换方法，而不是重试同一个调用。\n")
	b.WriteString("确实无法推进时，明确说明缺什么（凭据？范围？信息？），不要猜。\n")
}
