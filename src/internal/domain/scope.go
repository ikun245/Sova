package domain

import (
	"fmt"
	"net"
	"strings"
	"time"
)

// RiskLevel classifies what a command could do to a target. The level decides
// whether execution needs approval, not whether the command is "allowed" by
// scope — scope and risk are independent gates.
type RiskLevel string

const (
	// RiskPassive observes public data without touching the target
	// (DNS, WHOIS, certificate transparency).
	RiskPassive RiskLevel = "passive"
	// RiskLight connects but sends no attack payload (TCP connect, TLS
	// handshake, HEAD/GET).
	RiskLight RiskLevel = "light"
	// RiskActive probes for weaknesses with non-destructive payloads
	// (directory enumeration, parameter fuzzing, fingerprints).
	RiskActive RiskLevel = "active"
	// RiskIntrusive verifies exploitability or attempts credentials. This can
	// change target state and is never enabled by default.
	RiskIntrusive RiskLevel = "intrusive"
	// RiskCodeExecution runs a general-purpose interpreter (sh, python, java,
	// node). It sits above intrusive because argv inspection cannot bound what
	// the script does: it can reach any host, not just the declared target.
	// Enabled only through an explicit TargetScope.CodeExecution grant.
	RiskCodeExecution RiskLevel = "code_execution"
)

var riskRank = map[RiskLevel]int{
	RiskPassive:       0,
	RiskLight:         1,
	RiskActive:        2,
	RiskIntrusive:     3,
	RiskCodeExecution: 4,
}

// AtMost reports whether this level is within a ceiling.
func (r RiskLevel) AtMost(ceiling RiskLevel) bool {
	return riskRank[r] <= riskRank[ceiling]
}

// TargetScope is the authorization boundary for one engagement. Every network
// command is checked against it in code; model output is never trusted to
// decide whether a target is in scope.
//
// JSON tags are snake_case because this struct is also the API payload. Mixed
// casing between Go and JSON would force every client to guess field names,
// which is exactly the kind of information gap the API is supposed to avoid.
type TargetScope struct {
	ID       string `json:"id"`
	TenantID string `json:"tenant_id"`
	// Domains are allowed suffixes. "example.com" also permits
	// "api.example.com" but not "notexample.com".
	Domains []string `json:"domains"`
	// CIDRs are allowed networks.
	CIDRs []string `json:"cidrs"`
	// Ports restricts the target ports that may be touched. Empty means any.
	Ports []int `json:"ports"`
	// MaxRisk is the highest risk level this engagement authorizes.
	MaxRisk RiskLevel `json:"max_risk"`
	// MaxRatePerMinute throttles requests. Zero means unlimited.
	MaxRatePerMinute int `json:"max_rate_per_minute"`
	// ExpiresAt ends the authorization. A zero value means "no expiry".
	ExpiresAt time.Time `json:"expires_at"`
	// ApprovedBy and TicketID make the engagement auditable.
	ApprovedBy string `json:"approved_by"`
	TicketID   string `json:"ticket_id"`
}

// Target is one destination a command intends to reach.
type Target struct {
	Host string
	Port int
}

func (t Target) String() string {
	if t.Port > 0 {
		return fmt.Sprintf("%s:%d", t.Host, t.Port)
	}
	return t.Host
}

// ErrOutOfScope explains why a target was refused. It is deliberately specific
// so an operator can fix the scope, but it never reveals other targets.
type ErrOutOfScope struct {
	Target string
	Reason string
	// Expired distinguishes a closed authorization window from a target that
	// was never authorized, so callers can pick the right error code.
	Expired bool
}

func (e *ErrOutOfScope) Error() string {
	return fmt.Sprintf("target %s is out of scope: %s", e.Target, e.Reason)
}

// Code maps the refusal to the stable code a model branches on.
func (e *ErrOutOfScope) Code() ErrorCode {
	if e.Expired {
		return CodeScopeExpired
	}
	return CodeOutOfScope
}

// Allows reports whether a target is authorized. Resolution of a hostname to
// IPs happens in the caller (or runner) so DNS rebinding cannot bypass the
// CIDR check.
func (s TargetScope) Allows(target Target, now time.Time) error {
	if !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt) {
		return &ErrOutOfScope{
			Target:  target.String(),
			Reason:  "authorization expired at " + s.ExpiresAt.UTC().Format(time.RFC3339),
			Expired: true,
		}
	}

	host := strings.TrimSpace(strings.ToLower(target.Host))
	if host == "" {
		return &ErrOutOfScope{Target: target.String(), Reason: "empty host"}
	}

	if len(s.Ports) > 0 && target.Port > 0 && !containsInt(s.Ports, target.Port) {
		return &ErrOutOfScope{Target: target.String(), Reason: fmt.Sprintf("port %d is not in the authorized port list", target.Port)}
	}

	// An IP literal is checked against CIDRs only; a domain rule must not
	// silently authorize arbitrary addresses.
	if ip := net.ParseIP(host); ip != nil {
		if !s.allowsIP(ip) {
			return &ErrOutOfScope{Target: target.String(), Reason: "IP is not inside any authorized CIDR"}
		}
		return nil
	}

	if !s.allowsDomain(host) {
		return &ErrOutOfScope{Target: target.String(), Reason: "domain is not inside any authorized suffix"}
	}
	return nil
}

// AllowsIP reports whether an address is inside a declared CIDR. Callers use it
// to accept an internal target that the engagement listed explicitly, while a
// hostname resolving to the same address stays rejected unless declared.
func (s TargetScope) AllowsIP(ip net.IP) bool {
	return s.allowsIP(ip)
}

// allowsDomain matches by dot-boundary so "example.com" cannot be satisfied by
// "notexample.com" or "example.com.evil.test".
func (s TargetScope) allowsDomain(host string) bool {
	for _, raw := range s.Domains {
		domain := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(raw)), ".")
		if domain == "" {
			continue
		}
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}

func (s TargetScope) allowsIP(ip net.IP) bool {
	for _, raw := range s.CIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if network.Contains(ip) {
			return true
		}
	}
	return false
}

// Validate rejects a scope that would authorize everything. An empty scope is
// dangerous precisely because it looks harmless.
func (s TargetScope) Validate(now time.Time) error {
	if len(s.Domains) == 0 && len(s.CIDRs) == 0 {
		return fmt.Errorf("scope %q authorizes no targets: add at least one domain or CIDR", s.ID)
	}
	if s.MaxRisk == "" {
		return fmt.Errorf("scope %q has no max risk level", s.ID)
	}
	if _, ok := riskRank[s.MaxRisk]; !ok {
		return fmt.Errorf("scope %q has unknown max risk %q", s.ID, s.MaxRisk)
	}
	for _, raw := range s.CIDRs {
		if _, _, err := net.ParseCIDR(strings.TrimSpace(raw)); err != nil {
			return fmt.Errorf("scope %q has invalid CIDR %q", s.ID, raw)
		}
	}
	for _, domain := range s.Domains {
		domain = strings.TrimSpace(domain)
		if domain == "" {
			continue
		}
		// A bare "*" or "0.0.0.0/0"-style blanket is rejected: it is almost
		// always a mistake and it defeats the purpose of a scope.
		if domain == "*" {
			return fmt.Errorf("scope %q must not authorize every domain", s.ID)
		}
	}
	for _, cidr := range s.CIDRs {
		_, network, err := net.ParseCIDR(strings.TrimSpace(cidr))
		if err != nil {
			continue
		}
		ones, bits := network.Mask.Size()
		if ones == 0 {
			return fmt.Errorf("scope %q must not authorize the entire address space (%s)", s.ID, cidr)
		}
		if bits == 32 && ones > 24 || bits == 128 && ones > 64 {
			// Not an error in itself, but worth flagging in review: a /24 or
			// wider on a single engagement is usually a misconfiguration.
			continue
		}
	}
	return nil
}

func containsInt(values []int, want int) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
