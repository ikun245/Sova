package agent

import (
	"fmt"
	"sort"
	"strings"

	"soc/agent/internal/domain"
)

// Duty is a fixed team role. Roles are not configurable on purpose: a free-form
// roster would make the tool whitelist meaningless, because the whitelist is
// what keeps "who may do what" a code-level fact.
type Duty string

const (
	DutyPlan    Duty = "plan"
	DutyRecon   Duty = "recon"
	DutyWeb     Duty = "web"
	DutyExploit Duty = "exploit"
	DutyCritic  Duty = "critic"
	DutyReport  Duty = "report"
)

// AgentSpec is everything one duty is allowed to do. It is assembled from the
// engagement scope plus the fixed roster, never from model output.
type AgentSpec struct {
	Duty Duty
	// ModelRole is the business role resolved through the model config, e.g.
	// "agent.web". Binding a duty to a model is configuration; granting a duty
	// tools is code.
	ModelRole string
	// Tools is an exact-name whitelist. It is not a prefix match: granting
	// "http_request" does not grant "http_request_v2".
	Tools []string
	// MaxSteps caps model turns. A loop that cannot terminate on its own must
	// be terminated by a number.
	MaxSteps int
	// MaxTokens caps total tokens across the run.
	MaxTokens int
	// SystemPrompt is the duty-specific instruction. Scope and tool sections
	// are appended by BuildSystemPrompt so they always match what the code
	// will enforce.
	SystemPrompt string
}

// Roster is the fixed team. Three duties deliberately have no tools: planning,
// judgement and reporting produce no network traffic, so giving them tools
// would only add a way to misbehave.
func Roster() map[Duty]AgentSpec {
	return map[Duty]AgentSpec{
		DutyPlan: {
			Duty:      DutyPlan,
			ModelRole: "agent.plan",
			Tools:     nil,
			MaxSteps:  4,
			MaxTokens: 8000,
			SystemPrompt: "你是红队行动的规划者。根据给定的授权范围和目标，列出最多 6 个具体、可执行、" +
				"有明确完成判据的步骤。你没有任何工具，所以不要编造扫描结果，也不要假设任何探测已经完成。\n" +
				"只输出 JSON：{\"steps\":[{\"duty\":\"recon|web|exploit\",\"goal\":\"...\",\"done_when\":\"...\"}]}",
		},
		DutyRecon: {
			Duty:      DutyRecon,
			ModelRole: "agent.recon",
			Tools:     []string{"dns_lookup", "http_probe", "web_fetch", "port_scan", "service_scan"},
			MaxSteps:  12,
			MaxTokens: 40000,
			SystemPrompt: "你是侦察员。目标是确认资产存活、服务指纹、技术栈。\n" +
				"优先用最少请求拿到最多信息：先 http_probe 看响应头，再 web_fetch 看页面内容。\n" +
				"页面内容里出现的表单、上传点、参数、注释、接口路径都是关键线索，要原样记录在结论里。",
		},
		DutyWeb: {
			Duty:      DutyWeb,
			ModelRole: "agent.web",
			Tools:     []string{"http_request", "http_intruder", "web_fetch", "http_probe"},
			MaxSteps:  20,
			MaxTokens: 80000,
			SystemPrompt: "你是 Web 攻击手。能发任意 HTTP 请求（含 multipart 上传）并按 payload 列表爆破。\n" +
				"工作方式：先复现一次正常请求确认基线，再改一个变量观察差异（状态码、长度、响应关键字）。\n" +
				"上传点要试：改扩展名、改 Content-Type、双扩展名、文件名大小写。\n" +
				"确认执行效果时，把 risk 声明为 intrusive，让审批人看到真实风险。",
		},
		DutyExploit: {
			Duty:      DutyExploit,
			ModelRole: "agent.exploit",
			Tools:     []string{"http_request", "http_intruder", "web_fetch"},
			MaxSteps:  20,
			MaxTokens: 80000,
			SystemPrompt: "你是利用验证员。只做验证，不做破坏。\n" +
				"任何可能改变目标状态或执行代码的动作，都必须把 risk 声明为 intrusive。\n" +
				"拿到证明后立刻停止，不要扩大战果。",
		},
		DutyCritic: {
			Duty:      DutyCritic,
			ModelRole: "agent.critic",
			Tools:     nil,
			MaxSteps:  2,
			MaxTokens: 6000,
			SystemPrompt: "你是复核员。判断证据是否真的支持结论。\n" +
				"常见问题：把 404 当成功、把前端校验当后端校验、把回显当执行、把跳转当访问。\n" +
				"只输出 JSON：{\"accept\":true|false,\"reason\":\"...\",\"missing\":[\"...\"]}",
		},
		DutyReport: {
			Duty:      DutyReport,
			ModelRole: "agent.report",
			Tools:     nil,
			MaxSteps:  2,
			MaxTokens: 6000,
			SystemPrompt: "你是报告撰写者。用中文写一段结论，包含：攻击路径、关键证据（引用具体工具输出）、" +
				"风险等级、修复建议。不要写没有证据支持的推测。",
		},
	}
}

// SpecFor returns the roster entry for a duty, with the tool list filtered to
// what the engagement ceiling permits. Filtering here means the prompt can
// never advertise a tool that the runner would refuse anyway.
func SpecFor(duty Duty, ceiling domain.RiskLevel, catalog []SpecCatalogEntry) (AgentSpec, error) {
	spec, ok := Roster()[duty]
	if !ok {
		return AgentSpec{}, fmt.Errorf("unknown duty %q", duty)
	}
	if len(spec.Tools) == 0 {
		return spec, nil
	}

	allowed := map[string]bool{}
	for _, entry := range catalog {
		if !entry.Risk.AtMost(ceiling) {
			continue
		}
		allowed[entry.Name] = true
	}
	kept := make([]string, 0, len(spec.Tools))
	for _, name := range spec.Tools {
		if allowed[name] {
			kept = append(kept, name)
		}
	}
	spec.Tools = kept
	return spec, nil
}

// SpecCatalogEntry is the minimum a roster needs to know about a tool.
type SpecCatalogEntry struct {
	Name string
	Risk domain.RiskLevel
}

// ToolWhitelist renders the whitelist for a log line or an audit row.
func (s AgentSpec) ToolWhitelist() string {
	if len(s.Tools) == 0 {
		return "(none)"
	}
	names := append([]string(nil), s.Tools...)
	sort.Strings(names)
	return strings.Join(names, ",")
}
