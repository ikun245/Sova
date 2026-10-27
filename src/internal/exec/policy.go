package exec

import (
	"fmt"
	"path"
	"regexp"
	"strings"

	"soc/agent/internal/domain"
)

// Decision is the policy verdict for one command.
type Decision string

const (
	DecisionAllow Decision = "allow"
	DecisionAsk   Decision = "ask"
	DecisionDeny  Decision = "deny"
)

// Classification is what the policy knows about a command.
type Classification struct {
	Risk     domain.RiskLevel
	Decision Decision
	Reason   string
}

// Policy classifies commands before anything runs.
//
// Two independent gates apply, and this policy only covers the first:
//  1. may this command run at all, at this risk level?  (here)
//  2. is the target authorized by the engagement scope?  (Runner, in code)
//
// A command that is not recognised gets the most restrictive treatment rather
// than a guess: an unknown binary could be a renamed tool.
type Policy struct {
	// Ceiling is the maximum risk the engagement permits. Commands above it
	// are denied; commands at it are allowed; the one level below the ceiling
	// still requires approval when AskAbove is set.
	Ceiling domain.RiskLevel
	// AskAbove makes commands above this level require human approval instead
	// of running immediately. It must be at or below Ceiling.
	AskAbove domain.RiskLevel
	// Shell allows shell metacharacters. Disabled by default because a shell
	// turns a scoped argv into an arbitrary program.
	Shell bool
	// Interpreter permits general-purpose code runners (sh, python, java).
	// Interpreters are always "ask", never allow: the code is opaque, so a human
	// inspects each invocation.
	Interpreter bool
}

// toolRisk maps a binary to the risk it implies. Anything absent is unknown and
// therefore denied: a scanner we have not classified must be added on purpose.
var toolRisk = map[string]domain.RiskLevel{
	// Passive: public data, no packet reaches the target service.
	"dig": domain.RiskPassive, "nslookup": domain.RiskPassive, "host": domain.RiskPassive,
	"whois": domain.RiskPassive, "hostid": domain.RiskPassive,

	// Light: a connection or a single benign request.
	"curl": domain.RiskLight, "wget": domain.RiskLight, "nc": domain.RiskLight,
	"ncat": domain.RiskLight, "openssl": domain.RiskLight, "ping": domain.RiskLight,
	"traceroute": domain.RiskLight, "tracert": domain.RiskLight, "nc.subproj": domain.RiskLight,

	// Active: enumeration with non-destructive payloads.
	"nmap": domain.RiskActive, "masscan": domain.RiskActive, "ffuf": domain.RiskActive,
	"gobuster": domain.RiskActive, "feroxbuster": domain.RiskActive, "dirsearch": domain.RiskActive,
	"whatweb": domain.RiskActive, "nikto": domain.RiskActive, "nuclei": domain.RiskActive,
	"subfinder": domain.RiskActive, "amass": domain.RiskActive, "katana": domain.RiskActive,
	"httpx": domain.RiskActive, "wpscan": domain.RiskActive, "testssl": domain.RiskActive,

	// Intrusive: attempts exploitation or credentials. State-changing.
	"sqlmap": domain.RiskIntrusive, "hydra": domain.RiskIntrusive, "medusa": domain.RiskIntrusive,
	"john": domain.RiskIntrusive, "hashcat": domain.RiskIntrusive, "metasploit": domain.RiskIntrusive,
	"msfconsole": domain.RiskIntrusive, "searchsploit": domain.RiskIntrusive,
	"evil-winrm": domain.RiskIntrusive, "crackmapexec": domain.RiskIntrusive,
	"netexec": domain.RiskIntrusive, "responder": domain.RiskIntrusive,
}

// passiveTools never need a target: they only read public records.
var passiveTools = map[string]bool{
	"dig": true, "nslookup": true, "host": true, "whois": true, "hostid": true,
}

// shellOperators are the characters that would let one argv entry act as
// several commands. They are rejected unless Policy.Shell is explicitly set.
var shellOperators = []string{"|", "&", ";", "$(", "`", ">", "<", "\n", "&&", "||"}

// destructivePatterns never belong in authorized testing, whatever the risk
// level. These are checked before anything else because their blast radius is
// the operator's own host, not the target.
var destructivePatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)\brm\s+(-[a-z]*\s+)*-?[a-z]*[rf]`),
	regexp.MustCompile(`(?i)\bmkfs(\.\w+)?\b`),
	regexp.MustCompile(`(?i)\bdd\s+.*of=/dev/`),
	regexp.MustCompile(`(?i)\bshutdown\b|\breboot\b|\bhalt\b|\bpoweroff\b`),
	regexp.MustCompile(`(?i):\(\)\s*\{\s*:\|:&\s*\};:`), // fork bomb
	regexp.MustCompile(`(?i)\biptables\s+-F\b|\bnft\s+flush\b`),
	regexp.MustCompile(`(?i)>\s*/etc/(passwd|shadow|sudoers)`),
	regexp.MustCompile(`(?i)\bchmod\s+(-[a-z]+\s+)*777\s+/\s*$`),
	regexp.MustCompile(`(?i)\b(useradd|userdel|passwd)\b`),
	regexp.MustCompile(`(?i)\bcrontab\s+-r\b`),
	regexp.MustCompile(`(?i)\bsystemctl\s+(stop|disable|mask)\b`),
}

// baseName extracts the program name on both Unix and Windows paths. path.Base
// only understands "/", so a Windows-style "C:\tools\nmap.exe" would otherwise
// stay unrecognised and be denied on every Windows deployment.
func baseName(program string) string {
	normalized := strings.ReplaceAll(strings.TrimSpace(program), `\`, "/")
	base := strings.ToLower(path.Base(normalized))
	return strings.TrimSuffix(base, ".exe")
}

// Classify decides whether a command may run. argv is the program plus its
// arguments; no shell is assumed.
func (p Policy) Classify(argv []string) Classification {
	if len(argv) == 0 {
		return Classification{Decision: DecisionDeny, Risk: domain.RiskIntrusive, Reason: "empty command"}
	}

	program := strings.TrimSpace(argv[0])
	if program == "" {
		return Classification{Decision: DecisionDeny, Risk: domain.RiskIntrusive, Reason: "empty program name"}
	}

	base := baseName(program)
	interpreter := IsInterpreter(program)

	// A script legitimately contains ";", "|" and ">", so the metacharacter
	// ban only applies to non-interpreter commands. Interpreters are instead
	// gated by an explicit grant (see below), because no argv rule can bound
	// what a script does.
	if !p.Shell && !interpreter {
		joined := strings.Join(argv, " ")
		for _, operator := range shellOperators {
			if strings.Contains(joined, operator) {
				return Classification{
					Decision: DecisionDeny,
					Risk:     domain.RiskIntrusive,
					Reason:   fmt.Sprintf("shell metacharacter %q is not allowed; pass a single argv", operator),
				}
			}
		}
	}

	// Check destructive intent across the whole command line, including
	// arguments and inline interpreter code: "sh -c 'rm -rf /'" and
	// `python -c "os.system('mkfs ...')"` must both be caught.
	joined := strings.Join(argv, " ")
	for _, pattern := range destructivePatterns {
		if pattern.MatchString(joined) {
			return Classification{
				Decision: DecisionDeny,
				Risk:     domain.RiskIntrusive,
				Reason:   "command matches a destructive pattern that is never part of authorized testing",
			}
		}
	}

	if interpreter {
		return p.classifyInterpreter(base)
	}

	risk, known := toolRisk[base]
	if !known {
		return Classification{
			Decision: DecisionDeny,
			Risk:     domain.RiskIntrusive,
			Reason:   fmt.Sprintf("unrecognised program %q; add it to the tool policy deliberately", base),
		}
	}

	// Flags can make a benign binary dangerous: sqlmap --banner is a read,
	// sqlmap --os-shell is remote code execution. Escalation never lowers risk.
	if escalated, why := escalateRisk(base, argv, risk); escalated != risk {
		return p.Decide(escalated, explainEscalation(base, risk, escalated, why))
	}

	return p.Decide(risk, "")
}

// Decide applies the engagement ceiling to an already-known risk level. It is
// the single place where "allow", "ask" and "deny" are derived, so a built-in
// tool that declares its own risk cannot accidentally skip the ceiling.
func (p Policy) Decide(risk domain.RiskLevel, reason string) Classification {
	if !risk.AtMost(p.Ceiling) {
		return Classification{Risk: risk, Decision: DecisionDeny,
			Reason: join(reason, fmt.Sprintf("%s commands exceed this engagement's ceiling (%s)", risk, p.Ceiling))}
	}
	if !risk.AtMost(p.AskAbove) {
		return Classification{Risk: risk, Decision: DecisionAsk,
			Reason: join(reason, fmt.Sprintf("%s commands need approval in this engagement", risk))}
	}
	return Classification{Risk: risk, Decision: DecisionAllow,
		Reason: join(reason, fmt.Sprintf("%s command is within the approved ceiling", risk))}
}

func join(reason, suffix string) string {
	if reason == "" {
		return suffix
	}
	return reason + "; " + suffix
}

// NeedsTarget reports whether a program must be given a target so the runner
// can enforce scope. Passive lookups still take a host, so they are included.
func NeedsTarget(program string) bool {
	_, known := toolRisk[baseName(program)]
	return known
}

// IsPassive reports whether a program only reads public records and therefore
// never needs a CIDR check on the resolved address.
func IsPassive(program string) bool {
	return passiveTools[baseName(program)]
}
