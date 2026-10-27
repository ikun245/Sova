package domain

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"
)

// Finding kinds. A closed set, because a downstream consumer has to know what a
// finding means without reading prose.
const (
	// FindingRecon is an observation about the target: what is alive, what it
	// runs, what it exposes.
	FindingRecon = "recon"
	// FindingExposure is a reachable weakness that has been observed but not
	// exercised: an upload endpoint, an eval sink, an open admin path.
	FindingExposure = "exposure"
	// FindingAccess is confirmed control or data access. This is the class that
	// needs the strongest evidence, because it is the claim that pays out.
	FindingAccess = "access"
	// FindingNegative is a ruled-out hypothesis. It is a first-class result:
	// without it the next agent repeats the same failed attempt.
	FindingNegative = "negative"
)

var validFindingKinds = map[string]bool{
	FindingRecon:    true,
	FindingExposure: true,
	FindingAccess:   true,
	FindingNegative: true,
}

// Finding is the only thing that crosses between agents.
//
// Conversations do not propagate: a worker's transcript contains dead ends, and
// replaying it into the next agent invites the same mistakes at the same cost.
// A finding is the distilled claim plus the evidence that supports it, so a
// downstream agent starts from facts instead of from someone else's route.
type Finding struct {
	ID       string `json:"id"`
	TaskID   string `json:"task_id"`
	AgentKey string `json:"agent_key"`
	// Duty is the producing duty, kept so the report can attribute work.
	Duty   string `json:"duty"`
	Kind   string `json:"kind"`
	Target string `json:"target"`
	// Claim is one sentence that a reviewer can accept or reject.
	Claim string `json:"claim"`
	// Evidence is mandatory. A finding without a citation is an opinion, and an
	// opinion is exactly what an autonomous loop must not act on.
	Evidence   []EvidenceRef `json:"evidence"`
	Confidence float64       `json:"confidence"`
	// DedupKey normalises the claim so two agents reporting the same thing
	// converge on one row instead of duplicating the report.
	DedupKey string `json:"dedup_key"`
	// Rejected marks a finding the critic refused to accept. It is kept rather
	// than deleted so the report can say what was attempted and dismissed.
	Rejected   bool      `json:"rejected"`
	RejectNote string    `json:"reject_note,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// Validate enforces the grounding rule and the closed kind set. It is called
// before persistence, so an unsupported claim never becomes a fact that a later
// agent builds on.
func (f Finding) Validate() error {
	if strings.TrimSpace(f.Claim) == "" {
		return fmt.Errorf("finding has no claim")
	}
	if !validFindingKinds[f.Kind] {
		return fmt.Errorf("finding kind %q is not one of recon, exposure, access, negative", f.Kind)
	}
	if strings.TrimSpace(f.TaskID) == "" {
		return fmt.Errorf("finding has no task id")
	}
	if len(f.Evidence) == 0 {
		return fmt.Errorf("finding %q has no evidence; unsupported claims are not accepted", f.Claim)
	}
	for _, ref := range f.Evidence {
		if strings.TrimSpace(ref.Ref) == "" {
			return fmt.Errorf("finding %q cites evidence with no reference", f.Claim)
		}
	}
	if f.Confidence < 0 || f.Confidence > 1 {
		return fmt.Errorf("finding confidence %v is outside [0,1]", f.Confidence)
	}
	return nil
}

// NormalizedDedupKey derives a stable key from the meaning of the finding.
//
// Only kind, target and the claim participate. Evidence is excluded on purpose:
// two agents that independently confirm the same fact with different outputs
// have still confirmed the same fact, and rejecting the second one would lose
// corroboration.
func (f Finding) NormalizedDedupKey() string {
	claim := strings.ToLower(strings.Join(strings.Fields(f.Claim), " "))
	target := strings.ToLower(strings.TrimSpace(f.Target))
	sum := sha256.Sum256([]byte(f.Kind + "\x00" + target + "\x00" + claim))
	return hex.EncodeToString(sum[:16])
}

// FindingRepository persists findings for a task.
type FindingRepository interface {
	// CreateFinding inserts unless the (task, dedup_key) pair already exists.
	// It reports whether a new row was written, so a caller can distinguish
	// "recorded" from "already known" without a second query.
	CreateFinding(ctx context.Context, finding Finding) (Finding, bool, error)
	// ListFindings returns every finding for a task in creation order, including
	// rejected ones: the report has to be able to explain a dismissal.
	ListFindings(ctx context.Context, taskID string) ([]Finding, error)
	// RejectFinding marks a finding as refused by the critic, with the reason.
	RejectFinding(ctx context.Context, findingID, reason string) error
}
