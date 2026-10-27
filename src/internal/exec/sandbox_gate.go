package exec

import (
	"fmt"
	"strings"

	"soc/agent/internal/domain"
	"soc/agent/internal/sandbox"
)

// SandboxGate decides whether an interpreter may run in this environment.
//
// Both axes are checked because they answer different questions:
//   - the filesystem policy bounds where the process writes, and
//   - the network attestation bounds where it connects.
//
// A script is only as contained as the weaker of the two. Checking just one
// would produce a guarantee that does not exist.
type SandboxGate struct {
	// Policy is the per-call filesystem policy.
	Policy sandbox.Policy
	// Attestation is the operator's statement about egress.
	Attestation sandbox.Attestation
	// InterpreterApproval is required for every interpreter call, even when
	// both axes are confined: the code itself is opaque to policy.
	InterpreterApproval bool
}

// CheckInterpreter returns a coded error when an interpreter may not run.
func (g SandboxGate) CheckInterpreter(program string) error {
	if err := sandbox.CheckInterpreterEgress(program, g.Attestation); err != nil {
		return domain.WrapToolError(domain.CodePolicyDenied, err.Error(),
			"an operator must confine the worker's egress (container policy or egress proxy) "+
				"and record the attestation before interpreters can run", err).
			WithDetail("interpreter", baseName(program)).
			WithDetail("network", string(g.Attestation.Network))
	}

	// An unconfined filesystem does not by itself block an interpreter, but a
	// partially enforced policy must be visible: callers that need an absolute
	// boundary should not silently receive a weaker one.
	if g.Policy.Mode.Confined() && g.Policy.Enforcement == sandbox.EnforcementPartial {
		return domain.NewToolError(domain.CodePolicyDenied,
			fmt.Sprintf("sandbox backend %q only partially enforces %q", g.Policy.Backend, g.Policy.Mode),
			"an interpreter requires a fully enforced sandbox; use a container or a remote executor").
			WithDetail("backend", g.Policy.Backend).
			WithDetail("mode", string(g.Policy.Mode))
	}
	return nil
}

// WorkspaceRootFor returns the directory an interpreter should treat as its
// workspace, so relative paths land inside the writable area instead of the
// worker's own installation directory.
func (g SandboxGate) WorkspaceRootFor(fallback string) string {
	if g.Policy.Mode == sandbox.ModeWorkspaceWrite && g.Policy.WorkspaceRoot != "" {
		return g.Policy.WorkspaceRoot
	}
	return fallback
}

// describeSandbox renders the confinement for the audit log, so a reviewer can
// see what the process was actually allowed to do.
func describeSandbox(gate *SandboxGate) string {
	if gate == nil {
		return ""
	}
	parts := []string{string(gate.Policy.Mode)}
	if gate.Policy.Backend != "" {
		parts = append(parts, "backend="+gate.Policy.Backend)
	}
	if gate.Policy.Enforcement != "" {
		parts = append(parts, "enforcement="+string(gate.Policy.Enforcement))
	}
	if gate.Attestation.Network != "" {
		parts = append(parts, "network="+string(gate.Attestation.Network))
	}
	return strings.Join(parts, " ")
}
