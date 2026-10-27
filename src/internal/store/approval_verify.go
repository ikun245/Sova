package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"soc/agent/internal/domain"
)

// ConsumeApproval validates and spends an approval atomically.
//
// Every condition lives in the WHERE clause on purpose: a read-then-update would
// let two concurrent workers both observe "approved, unused, matching" and both
// proceed, which is exactly the replay the approval is supposed to prevent.
func (p *Postgres) ConsumeApproval(ctx context.Context, check domain.ApprovalCheck) (domain.Approval, error) {
	if check.ApprovalID == "" {
		return domain.Approval{}, domain.NewToolError(domain.CodeApprovalRequired,
			"this command needs a human approval",
			"request approval, then retry with the approval id")
	}

	var approval domain.Approval
	var argv []byte
	var risk string
	var usedAt sql.NullTime

	err := p.db.QueryRowContext(ctx, `
		UPDATE scope_approvals
		SET used_at = now()
		WHERE id = $1
		  AND scope_id = $2
		  AND target = $3
		  AND argv = $4
		  AND decision = 'approved'
		  AND used_at IS NULL
		  AND expires_at > now()
		RETURNING id, scope_id, target, argv, risk, decision, requested_by,
		          COALESCE(decided_by, ''), COALESCE(reason, ''), expires_at, created_at,
		          decided_at, used_at`,
		check.ApprovalID, check.ScopeID, check.Target, []byte(check.Argv),
	).Scan(&approval.ID, &approval.ScopeID, &approval.Target, &argv, &risk, &approval.Decision,
		&approval.RequestedBy, &approval.DecidedBy, &approval.Reason, &approval.ExpiresAt,
		&approval.CreatedAt, &approval.DecidedAt, &usedAt)

	if err == nil {
		approval.Argv = argv
		approval.Risk = domain.RiskLevel(risk)
		return approval, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return domain.Approval{}, fmt.Errorf("consume approval: %w", err)
	}

	// The row was not consumable. Diagnose precisely so the caller gets an
	// actionable code instead of a generic denial.
	return domain.Approval{}, p.diagnoseApproval(ctx, check)
}

// diagnoseApproval explains why an approval could not be consumed. The returned
// codes are stable so a model can tell "ask a human again" apart from "you sent
// the wrong id" apart from "this was already used".
func (p *Postgres) diagnoseApproval(ctx context.Context, check domain.ApprovalCheck) error {
	var (
		scopeID, target, decision string
		argv                      []byte
		expiresAt                 time.Time
		usedAt                    sql.NullTime
	)
	err := p.db.QueryRowContext(ctx, `
		SELECT scope_id, target, argv, decision, expires_at, used_at
		FROM scope_approvals WHERE id = $1`, check.ApprovalID,
	).Scan(&scopeID, &target, &argv, &decision, &expiresAt, &usedAt)

	if errors.Is(err, sql.ErrNoRows) {
		return domain.NewToolError(domain.CodeApprovalMismatch,
			"the supplied approval id does not exist",
			"request a new approval; do not invent ids").
			WithDetail("approval_id", check.ApprovalID)
	}
	if err != nil {
		return fmt.Errorf("diagnose approval: %w", err)
	}

	now := check.At
	if now.IsZero() {
		now = time.Now()
	}

	switch {
	case decision == domain.ApprovalRejected:
		return domain.NewToolError(domain.CodeApprovalRejected,
			"a human rejected this command",
			"do not retry the same command; choose a different approach or escalate").
			WithDetail("approval_id", check.ApprovalID)
	case decision == domain.ApprovalExpired:
		return domain.NewToolError(domain.CodeApprovalMismatch,
			"the approval expired because its scope was revoked",
			"request approval under a valid scope").
			WithDetail("approval_id", check.ApprovalID)
	case usedAt.Valid:
		return domain.NewToolError(domain.CodeApprovalConsumed,
			"this approval was already used for a previous command",
			"one approval authorizes one call; request a new approval").
			WithDetail("approval_id", check.ApprovalID)
	case !now.Before(expiresAt):
		return domain.NewToolError(domain.CodeApprovalRequired,
			"the approval has expired",
			"request a fresh approval").
			WithDetail("approval_id", check.ApprovalID)
	case decision != domain.ApprovalApproved:
		return domain.NewToolError(domain.CodeApprovalRequired,
			"the approval is still pending a human decision",
			"wait for the decision, then retry").
			WithDetail("approval_id", check.ApprovalID)
	case scopeID != check.ScopeID:
		return domain.NewToolError(domain.CodeApprovalMismatch,
			"the approval belongs to a different engagement scope",
			"request approval under the scope you are operating in").
			WithDetail("approval_id", check.ApprovalID).
			WithDetail("approval_scope", scopeID)
	case target != check.Target:
		return domain.NewToolError(domain.CodeApprovalMismatch,
			"the approval was granted for a different target",
			"request approval for this exact target").
			WithDetail("approval_id", check.ApprovalID).
			WithDetail("approved_target", target)
	default:
		// Same scope and target, so the command itself must differ.
		return domain.NewToolError(domain.CodeApprovalMismatch,
			"the approval was granted for a different command",
			"request approval for this exact command").
			WithDetail("approval_id", check.ApprovalID).
			WithDetail("approved_argv", string(argv))
	}
}
