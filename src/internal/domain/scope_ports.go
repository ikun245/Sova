package domain

import (
	"context"
	"encoding/json"
	"time"
)

// Approval decisions. A pending approval is the only state that resumes work.
const (
	ApprovalPending  = "pending"
	ApprovalApproved = "approved"
	ApprovalRejected = "rejected"
	ApprovalExpired  = "expired"
)

// Approval is a human decision on one specific command against one specific
// target. It authorizes that exact call, not "this tool" in general.
type Approval struct {
	ID          string          `json:"id"`
	ScopeID     string          `json:"scope_id"`
	Target      string          `json:"target"`
	Argv        json.RawMessage `json:"argv"`
	Risk        RiskLevel       `json:"risk"`
	Decision    string          `json:"decision"`
	RequestedBy string          `json:"requested_by"`
	DecidedBy   string          `json:"decided_by,omitempty"`
	Reason      string          `json:"reason,omitempty"`
	ExpiresAt   time.Time       `json:"expires_at"`
	CreatedAt   time.Time       `json:"created_at"`
	DecidedAt   *time.Time      `json:"decided_at,omitempty"`
}

// Usable reports whether this approval may authorize a call right now.
func (a Approval) Usable(now time.Time) bool {
	return a.Decision == ApprovalApproved && now.Before(a.ExpiresAt)
}

// ScopeRecord is a stored engagement scope plus the workspace it belongs to.
type ScopeRecord struct {
	Scope       TargetScope
	WorkspaceID string
	RevokedAt   *time.Time
}

// Active reports whether the scope may still be relied on.
func (r ScopeRecord) Active(now time.Time) bool {
	if r.RevokedAt != nil {
		return false
	}
	return r.Scope.ExpiresAt.IsZero() || now.Before(r.Scope.ExpiresAt)
}

// ScopeRepository persists engagement scopes and per-command approvals.
type ScopeRepository interface {
	// CreateScope stores a scope. The caller must already have validated it and
	// recorded who approved it; this method refuses an expired or blanket scope.
	CreateScope(ctx context.Context, workspaceID string, scope TargetScope) (TargetScope, error)
	GetScope(ctx context.Context, id string) (ScopeRecord, error)
	ListScopes(ctx context.Context, workspaceID string, includeRevoked bool) ([]ScopeRecord, error)
	RevokeScope(ctx context.Context, id, revokedBy string) error

	// RequestApproval records a pending request. It reports false when an
	// equivalent request is already pending, so the human queue stays clean.
	RequestApproval(ctx context.Context, approval Approval) (Approval, bool, error)
	// DecideApproval records the human decision and returns the stored row.
	DecideApproval(ctx context.Context, id, decision, decidedBy, reason string) (Approval, error)
	GetApproval(ctx context.Context, id string) (Approval, error)
	ListApprovals(ctx context.Context, decision string, limit int) ([]Approval, error)
}
