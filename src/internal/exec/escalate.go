package exec

import (
	"fmt"
	"regexp"
	"strings"

	"soc/agent/internal/domain"
)

// escalatingRules raise a command's risk based on its arguments.
//
// Classifying by binary alone is not enough: "sqlmap --banner" only reads a
// banner, while "sqlmap --os-shell" gives remote command execution. Both are
// the same executable at the same nominal level, so the flags, not the program
// name, must decide.
var escalatingRules = map[string][]escalation{
	"sqlmap": {
		{pattern: regexp.MustCompile(`(?i)--os-(shell|pwn|cmd)`), to: domain.RiskIntrusive,
			why: "sqlmap --os-shell/--os-pwn/--os-cmd gives command execution on the target"},
		{pattern: regexp.MustCompile(`(?i)--file-(read|write|dest)`), to: domain.RiskIntrusive,
			why: "sqlmap file read/write touches the target filesystem"},
		{pattern: regexp.MustCompile(`(?i)--sql-shell|--shell\b`), to: domain.RiskIntrusive,
			why: "an interactive SQL shell is state-changing exploration"},
		{pattern: regexp.MustCompile(`(?i)--(dump|dump-all|passwords|users|roles|priv)\b`), to: domain.RiskIntrusive,
			why: "credential and database dumping exfiltrates target data"},
	},
	"nmap": {
		{pattern: regexp.MustCompile(`(?i)--script\s*=?\s*["']?(vuln|exploit|brute|dos)`), to: domain.RiskIntrusive,
			why: "nmap NSE vulnerability/exploit/brute scripts can change target state"},
		{pattern: regexp.MustCompile(`(?i)--script-args`), to: domain.RiskIntrusive,
			why: "NSE script arguments can trigger intrusive behaviour"},
	},
	"nuclei": {
		{pattern: regexp.MustCompile(`(?i)-(-)?(code|headless)\b`), to: domain.RiskIntrusive,
			why: "nuclei code/headless templates execute logic, not just requests"},
	},
	"ffuf": {
		{pattern: regexp.MustCompile(`(?i)-X\s*(POST|PUT|DELETE|PATCH)`), to: domain.RiskIntrusive,
			why: "state-changing HTTP methods are not enumeration"},
	},
	"curl": {
		{pattern: regexp.MustCompile(`(?i)(^|\s)(-T|--upload-file|-d|--data|-X\s*(POST|PUT|DELETE|PATCH))`), to: domain.RiskActive,
			why: "sending a request body or a state-changing method is no longer a read-only probe"},
		{pattern: regexp.MustCompile(`(?i)(^|\s)-o\s|(^|\s)-O\b|--output`), to: domain.RiskActive,
			why: "writing downloaded content to disk changes the worker, not just the target"},
	},
}

type escalation struct {
	pattern *regexp.Regexp
	to      domain.RiskLevel
	why     string
}

// escalateRisk returns the effective risk for a command, raising the binary's
// baseline when its flags make it more dangerous. It never lowers risk.
func escalateRisk(program string, argv []string, base domain.RiskLevel) (domain.RiskLevel, string) {
	base_ := baseName(program)
	rules, ok := escalatingRules[base_]
	if !ok {
		return base, ""
	}

	joined := strings.Join(argv, " ")
	effective := base
	reason := ""
	for _, rule := range rules {
		if !rule.pattern.MatchString(joined) {
			continue
		}
		if riskRankLocal(rule.to) > riskRankLocal(effective) {
			effective = rule.to
			reason = rule.why
		}
	}
	return effective, reason
}

func riskRankLocal(level domain.RiskLevel) int {
	switch level {
	case domain.RiskPassive:
		return 0
	case domain.RiskLight:
		return 1
	case domain.RiskActive:
		return 2
	case domain.RiskIntrusive:
		return 3
	default:
		return 4
	}
}

// explainEscalation builds the reason string shown to the model and the audit
// log when flags raised the risk.
func explainEscalation(binary string, from, to domain.RiskLevel, why string) string {
	return fmt.Sprintf("%s is normally %s, but these flags raise it to %s: %s", binary, from, to, why)
}
