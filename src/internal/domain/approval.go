package domain

import (
	"context"
	"encoding/json"
	"time"
)

// ApprovalVerifier checks that an approval actually authorizes one specific
// command and atomically spends it.
//
// This is the piece that makes "ask" a real gate rather than a parameter check:
// an approval is bound to (scope, target, argv), is single-use, and must still
// be approved and unexpired at the moment of use. Anything less lets a model
// recycle one approval for every later command.
type ApprovalVerifier interface {
	// ConsumeApproval validates and spends an approval in one atomic step, so
	// two concurrent calls cannot both claim it. It returns a coded error on
	// any mismatch, denial, expiry, or prior consumption.
	ConsumeApproval(ctx context.Context, req ApprovalCheck) (Approval, error)
}

// ApprovalCheck is the exact binding an approval must match.
type ApprovalCheck struct {
	ApprovalID string
	ScopeID    string
	Target     string
	Argv       json.RawMessage
	// At is the moment of use; zero means "now". Injectable for tests.
	At time.Time
}

// NormalizeArgv renders argv in a canonical form so an approval matches the
// command byte-for-byte rather than by a loose comparison.
//
// Order matters: ["nmap","-sV","host"] and ["nmap","host","-sV"] are different
// commands to a shell, so they must be different commands here too.
func NormalizeArgv(argv []string) json.RawMessage {
	encoded, err := json.Marshal(argv)
	if err != nil {
		return json.RawMessage("[]")
	}
	return encoded
}
