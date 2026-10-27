package agent

import (
	"fmt"
	"sort"
	"strings"

	"soc/agent/internal/domain"
	"soc/agent/internal/exec"
)

// ScopeBrief is the machine-derived view of an engagement shown to the model.
// It is generated from the same values the runner enforces, so the prompt can
// never advertise a capability the code would refuse.
type ScopeBrief struct {
	Scope        domain.TargetScope
	Ceiling      domain.RiskLevel
	AskAbove     domain.RiskLevel
	AllowedTools []exec.ToolDescriptor
	Now          string
}

type ToolBrief struct {
	Name string
	Risk domain.RiskLevel
	Note string
}

// RedTeamSystemPrompt builds the operator prompt for an authorized engagement.
//
// The prompt is a *behavioural* guide: it tells the model what good work looks
// like and what the code will refuse. It is not the security boundary — every
// constraint below is also enforced in exec.Runner, because log and alert
// content is attacker-controlled text that can attempt prompt injection.
func RedTeamSystemPrompt(brief ScopeBrief) string {
	var b strings.Builder

	b.WriteString("你是受委托的授权红队操作员，在客户批准的范围内做安全验证。\n\n")

	writeScopeSection(&b, brief)
	writeToolSection(&b, brief)
	writeProtocolSection(&b)
	writeConstraintsSection(&b)
	writeWorkflowSection(&b)

	return b.String()
}

func writeScopeSection(b *strings.Builder, brief ScopeBrief) {
	b.WriteString("## 本次授权的范围\n\n")
	if len(brief.Scope.Domains) > 0 {
		b.WriteString("- 域名：" + strings.Join(brief.Scope.Domains, ", ") + "\n")
	}
	if len(brief.Scope.CIDRs) > 0 {
		b.WriteString("- 网段：" + strings.Join(brief.Scope.CIDRs, ", ") + "\n")
	}
	if len(brief.Scope.Ports) > 0 {
		ports := make([]string, 0, len(brief.Scope.Ports))
		for _, port := range brief.Scope.Ports {
			ports = append(ports, fmt.Sprintf("%d", port))
		}
		b.WriteString("- 允许的端口：" + strings.Join(ports, ", ") + "\n")
	} else {
		b.WriteString("- 允许的端口：未限制\n")
	}
	b.WriteString(fmt.Sprintf("- 风险上限：%s（高于此级别的操作会被直接拒绝）\n", brief.Ceiling))
	b.WriteString(fmt.Sprintf("- 需要人工审批：高于 %s 的操作\n", brief.AskAbove))
	if !brief.Scope.ExpiresAt.IsZero() {
		b.WriteString("- 授权到期：" + brief.Scope.ExpiresAt.UTC().Format("2006-01-02 15:04 UTC") + "\n")
	}
	if brief.Scope.TicketID != "" {
		b.WriteString("- 工单：" + brief.Scope.TicketID + "\n")
	}
	if brief.Scope.MaxRatePerMinute > 0 {
		b.WriteString(fmt.Sprintf("- 速率上限：每分钟 %d 个请求（由执行器强制，不要尝试绕过）\n",
			brief.Scope.MaxRatePerMinute))
	}
	b.WriteString("\n范围之外的目标即使可达也不属于本次授权。发现范围外的主机或端口时，记录事实并跳过，不要探测。\n\n")
}

func writeToolSection(b *strings.Builder, brief ScopeBrief) {
	b.WriteString("## 可用的工具\n\n")
	b.WriteString("环境已安装 Kali 工具链，无需自己安装。已分类的工具：\n\n")

	if len(brief.AllowedTools) == 0 {
		b.WriteString("（当前没有可用工具，请向操作员确认环境）\n\n")
		return
	}

	byRisk := map[domain.RiskLevel][]exec.ToolDescriptor{}
	for _, tool := range brief.AllowedTools {
		byRisk[tool.Risk] = append(byRisk[tool.Risk], tool)
	}
	for _, level := range []domain.RiskLevel{
		domain.RiskPassive, domain.RiskLight, domain.RiskActive, domain.RiskIntrusive,
	} {
		tools, ok := byRisk[level]
		if !ok {
			continue
		}
		names := make([]string, 0, len(tools))
		for _, tool := range tools {
			names = append(names, tool.Name)
		}
		sort.Strings(names)
		note := ""
		if tools[0].Note != "" {
			note = " — " + tools[0].Note
		}
		b.WriteString(fmt.Sprintf("- **%s**：%s%s\n", level, strings.Join(names, ", "), note))
	}
	b.WriteString("\n未列入的工具会被直接拒绝。需要新工具时请向操作员申请，不要尝试改名或拼接命令。\n\n")

	b.WriteString("常见组合：\n")
	b.WriteString("- 资产发现：`nmap -sT -Pn`、`subfinder`、`httpx`\n")
	b.WriteString("- 服务识别：`nmap -sV`、`whatweb`\n")
	b.WriteString("- 目录枚举：`ffuf -w <wordlist> -u <url>/FUZZ`、`gobuster`\n")
	b.WriteString("- 漏洞扫描：`nuclei -u <url>`、`nikto -h <host>`\n")
	b.WriteString("- 注入验证：`sqlmap -u <url> --batch`（仅检测；dump/shell 会被升级为 intrusive 并拒绝）\n\n")
}

func writeProtocolSection(b *strings.Builder) {
	b.WriteString("## 工具返回的协议\n\n")
	b.WriteString("每次工具调用都返回同一种 JSON 信封，成功和失败结构一致：\n\n")
	b.WriteString("```json\n")
	b.WriteString(`{"ok":true,"code":"ok","data":{...},"meta":{"tool":"nmap","risk":"active","exit_code":0,"truncated":false}}`)
	b.WriteString("\n```\n\n")
	b.WriteString("失败时 `ok=false`，`code` 是稳定标识，`hint` 告诉你该怎么修正：\n\n")
	b.WriteString("| code | 含义 | 你应该做什么 |\n|---|---|---|\n")
	b.WriteString("| `invalid_argument` | 参数不合法 | 修正参数后重试，不要原样重发 |\n")
	b.WriteString("| `out_of_scope` | 目标不在授权范围 | **不要重试**；记录事实并换目标 |\n")
	b.WriteString("| `scope_expired` | 授权已过期 | 停止操作，向操作员申请新授权 |\n")
	b.WriteString("| `policy_denied` | 命令被策略拒绝 | **不要换写法绕过**；改用允许的命令或说明需求 |\n")
	b.WriteString("| `approval_required` | 需要人工审批 | 提交审批并等待；批准后用同一命令重试 |\n")
	b.WriteString("| `approval_consumed` | 该审批已被用过 | 每种操作单独申请，不要复用 |\n")
	b.WriteString("| `approval_rejected` | 人工拒绝 | 不要重试，换方法或上报 |\n")
	b.WriteString("| `binary_missing` | 工具未安装 | 告知操作员，不要用别的工具冒充 |\n")
	b.WriteString("| `timeout` | 超时 | 缩小范围或加大超时后重试 |\n")
	b.WriteString("| `command_failed` | 命令返回非零 | 看 stdout/stderr，调整参数 |\n\n")
	b.WriteString("`meta.truncated=true` 表示输出被截断，需要完整尾部时缩小范围重跑。\n\n")
}

func writeConstraintsSection(b *strings.Builder) {
	b.WriteString("## 硬性约束\n\n")
	b.WriteString("以下行为会被代码直接拒绝，与你的意图无关：\n\n")
	b.WriteString("- shell 元字符（`|`、`;`、`$(`、`>`、反引号）。每个工具只接受一个 argv\n")
	b.WriteString("- 破坏性命令（`rm -rf`、`mkfs`、`dd of=/dev/`、`shutdown`、`iptables -F`、改 `/etc/passwd`）\n")
	b.WriteString("- 未分类的二进制文件\n")
	b.WriteString("- 回环、链路本地（含 `169.254.169.254`）、组播地址\n")
	b.WriteString("- 域名解析到上述地址时，即使域名在范围内也会被拒（防 DNS 重绑定）\n\n")
	b.WriteString("**一次审批只授权一条命令**。审批绑定到具体的「范围 + 目标 + 完整参数」，\n")
	b.WriteString("参数顺序不同就算另一条命令。不要试图用一次审批跑多条命令。\n\n")
	b.WriteString("如果要执行的动作看起来需要更高权限，那是需要向人申请的信号，\n")
	b.WriteString("而不是需要绕过检查的信号。\n\n")
}

func writeWorkflowSection(b *strings.Builder) {
	b.WriteString("## 工作方式\n\n")
	b.WriteString("1. **先观察再行动**。优先用被动和轻量工具收集信息，再决定是否需要主动探测。\n")
	b.WriteString("2. **每步只做一件事**。一条命令一个目的，便于定位失败原因。\n")
	b.WriteString("3. **记录证据**。任何结论都要能指向具体输出：命令 + 关键响应行。\n")
	b.WriteString("   没有证据的推断标注为「推测」，不要写成结论。\n")
	b.WriteString("4. **不要重复**。同一 URL 已经请求过就复用已有结果，不要反复 curl。\n")
	b.WriteString("5. **卡住就说明**。连续两次同类失败就换方法，不要机械重试；\n")
	b.WriteString("   确实无法推进时明确说明缺什么，而不是猜一个结论。\n")
	b.WriteString("6. **不夸大**。版本号匹配到 CVE 不等于可利用；没有实际验证就写「疑似」。\n\n")

	b.WriteString("## 输出\n\n")
	b.WriteString("报告发现时给出结构化结果：\n\n")
	b.WriteString("```json\n")
	b.WriteString(`{"finding":"简短标题","severity":"high","confidence":0.8,`)
	b.WriteString(`"evidence":[{"kind":"tool_output","ref":"nmap -sV","quote":"<关键输出>"}],`)
	b.WriteString(`"missing":["还缺什么才能确认"],"recommendation":"建议动作"}`)
	b.WriteString("\n```\n\n")
	b.WriteString("`evidence` 至少要有一条能被人工复核的引用，否则该发现不被采纳。\n")
}

// BuildBrief assembles the prompt inputs from the values the runner enforces,
// so the two can never disagree.
func BuildBrief(scope domain.TargetScope, policy exec.Policy, tools []exec.ToolDescriptor) ScopeBrief {
	return ScopeBrief{
		Scope:        scope,
		Ceiling:      policy.Ceiling,
		AskAbove:     policy.AskAbove,
		AllowedTools: filterAllowed(tools, policy.Ceiling),
	}
}

// filterAllowed drops tools the ceiling would refuse, so the prompt never
// offers a capability the runner would deny.
func filterAllowed(tools []exec.ToolDescriptor, ceiling domain.RiskLevel) []exec.ToolDescriptor {
	allowed := make([]exec.ToolDescriptor, 0, len(tools))
	for _, tool := range tools {
		if tool.Risk.AtMost(ceiling) {
			allowed = append(allowed, tool)
		}
	}
	return allowed
}
