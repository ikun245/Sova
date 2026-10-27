package sandbox

import (
	"fmt"
	"strings"
)

// NetworkConfinement describes whether a process can reach hosts that the
// engagement scope does not list.
//
// This is deliberately separate from Mode. A filesystem jail says nothing about
// sockets: `read-only` python can still POST your database to any host. The
// upstream sandbox vocabulary omits network for exactly this reason, so treating
// "sandboxed" as "network-safe" would be a false guarantee.
//
// Only general-purpose interpreters need this. A tool like nmap is given one
// target on its command line, so the runner can check that target directly. A
// script chooses its own destinations at runtime, so the check must move to the
// environment.
type NetworkConfinement string

const (
	// NetworkUnknown means nobody stated how egress is restricted. Treated as
	// unconfined: absence of a claim is not evidence of confinement.
	NetworkUnknown NetworkConfinement = ""
	// NetworkUnconfined means the process can reach any host. Running an
	// interpreter here makes scope enforcement unverifiable.
	NetworkUnconfined NetworkConfinement = "unconfined"
	// NetworkEgressFiltered means traffic leaves through a proxy or firewall
	// restricted to the engagement. The interpreter may still be uncooperative,
	// but it cannot reach out-of-scope hosts.
	NetworkEgressFiltered NetworkConfinement = "egress-filtered"
	// NetworkIsolated means the process has no network at all. Suitable for
	// local data processing, not for anything that must talk to a target.
	NetworkIsolated NetworkConfinement = "isolated"
)

// Confined reports whether egress is restricted enough to run arbitrary code
// while keeping the scope meaningful.
func (n NetworkConfinement) Confined() bool {
	return n == NetworkEgressFiltered || n == NetworkIsolated
}

// Valid reports whether the value is a known state.
func (n NetworkConfinement) Valid() bool {
	switch n {
	case NetworkUnknown, NetworkUnconfined, NetworkEgressFiltered, NetworkIsolated:
		return true
	}
	return false
}

// ErrNetworkUnconfined means an interpreter was requested in an environment
// where its egress cannot be bounded, so its targets cannot be verified.
type ErrNetworkUnconfined struct {
	Interpreter string
	State       NetworkConfinement
}

func (e *ErrNetworkUnconfined) Error() string {
	state := string(e.State)
	if state == "" {
		state = "unspecified"
	}
	return fmt.Sprintf(
		"%s runs arbitrary code, but network egress is %s: its destinations cannot be verified against the scope",
		e.Interpreter, state)
}

// Attestation is the operator's statement about the worker's environment. It is
// required before any interpreter runs, because the runner cannot inspect what a
// script will do.
type Attestation struct {
	Network NetworkConfinement
	// AttestedBy records who confirmed the environment. Without a name the
	// claim is not auditable, so it does not count.
	AttestedBy string
	// Note explains the mechanism (container policy, egress proxy, no route).
	Note string
}

// Recorded reports whether the attestation has a responsible party.
func (a Attestation) Recorded() bool {
	return strings.TrimSpace(a.AttestedBy) != ""
}

// CheckInterpreterEgress decides whether an interpreter may run.
//
// Both conditions are required and neither is a formality:
//   - a named operator attests to the environment, and
//   - egress is actually restricted.
//
// A recorded attestation of "unconfined" is an explicit refusal, not a
// loophole: writing it down makes the risk auditable rather than hidden.
func CheckInterpreterEgress(interpreter string, attestation Attestation) error {
	if !attestation.Network.Valid() {
		return fmt.Errorf("unknown network confinement state %q", attestation.Network)
	}
	if !attestation.Recorded() {
		return &ErrNetworkUnconfined{Interpreter: interpreter, State: attestation.Network}
	}
	if !attestation.Network.Confined() {
		return &ErrNetworkUnconfined{Interpreter: interpreter, State: attestation.Network}
	}
	return nil
}
