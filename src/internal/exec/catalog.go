package exec

import (
	"sort"

	"soc/agent/internal/domain"
)

// ToolDescriptor is the model-facing metadata of a classified binary. It lets a
// prompt builder describe capabilities without reaching into the policy tables.
type ToolDescriptor struct {
	Name string
	Risk domain.RiskLevel
	Note string
}

// Notes explain what a tool is for, so the prompt can group them usefully
// instead of dumping a bare list of binary names.
var toolNotes = map[string]string{
	"dig":          "DNS 查询，只读公开记录",
	"nslookup":     "DNS 查询，只读公开记录",
	"whois":        "注册信息查询，只读公开记录",
	"curl":         "HTTP 请求，可用于验证单个端点",
	"wget":         "HTTP 下载",
	"nc":           "TCP 连通性检查",
	"openssl":      "TLS 握手与证书检查",
	"ping":         "ICMP 可达性",
	"nmap":         "端口与服务识别；带 vuln 脚本会升级为 intrusive",
	"masscan":      "大范围端口扫描，速率由执行器限制",
	"ffuf":         "目录与参数枚举",
	"gobuster":     "目录与子域枚举",
	"feroxbuster":  "递归目录枚举",
	"dirsearch":    "目录枚举",
	"whatweb":      "Web 指纹识别",
	"nikto":        "Web 服务器扫描",
	"nuclei":       "模板化漏洞扫描；code/headless 模板会升级为 intrusive",
	"subfinder":    "被动子域枚举",
	"amass":        "子域与资产枚举",
	"katana":       "Web 爬虫",
	"httpx":        "HTTP 存活与指纹探测",
	"wpscan":       "WordPress 扫描",
	"testssl":      "TLS 配置检查",
	"sqlmap":       "SQL 注入检测；dump/os-shell 会升级为 intrusive 并被拒绝",
	"hydra":        "口令尝试，默认不在任何授权范围",
	"medusa":       "口令尝试，默认不在任何授权范围",
	"metasploit":   "利用框架，默认不在任何授权范围",
	"msfconsole":   "利用框架，默认不在任何授权范围",
	"searchsploit": "本地漏洞库检索",
	"evil-winrm":   "远程管理，默认不在任何授权范围",
	"crackmapexec": "横向移动工具，默认不在任何授权范围",
	"netexec":      "横向移动工具，默认不在任何授权范围",
	"responder":    "投毒工具，默认不在任何授权范围",
	"john":         "离线口令破解",
	"hashcat":      "离线口令破解",
	"traceroute":   "路径追踪",
	"tracert":      "路径追踪",
	"ncat":         "TCP 连通性检查",
	"host":         "DNS 查询，只读公开记录",
	"hostid":       "本地信息，只读",
}

// Descriptors lists every classified binary with its risk and a short note.
// The list is sorted by name so prompts built from it are stable across runs.
func Descriptors() []ToolDescriptor {
	out := make([]ToolDescriptor, 0, len(toolRisk))
	for name, risk := range toolRisk {
		out = append(out, ToolDescriptor{Name: name, Risk: risk, Note: toolNotes[name]})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// RiskOf reports a binary's baseline risk, for callers that need the value
// without the whole classification.
func RiskOf(program string) (domain.RiskLevel, bool) {
	risk, ok := toolRisk[baseName(program)]
	return risk, ok
}
