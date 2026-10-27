package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"soc/agent/internal/domain"
)

var (
	ErrScopeNotFound     = errors.New("scope not found")
	ErrApprovalNotFound  = errors.New("approval not found")
	ErrScopeExpired      = errors.New("scope has already expired")
	ErrInvalidTransition = errors.New("approval is not pending")
)

func (p *Postgres) CreateScope(ctx context.Context, workspaceID string, scope domain.TargetScope) (domain.TargetScope, error) {
	now := time.Now()
	// The database is the last line of defence: a scope that authorizes
	// everything, or arrives already expired, must never be stored.
	if err := scope.Validate(now); err != nil {
		return domain.TargetScope{}, err
	}
	if !scope.ExpiresAt.IsZero() && !scope.ExpiresAt.After(now) {
		return domain.TargetScope{}, ErrScopeExpired
	}
	if scope.ApprovedBy == "" || scope.TicketID == "" {
		return domain.TargetScope{}, fmt.Errorf("scope requires approved_by and ticket_id")
	}

	_, err := p.db.ExecContext(ctx, `
		INSERT INTO scopes (id, tenant_id, workspace_id, domains, cidrs, ports, max_risk,
		                    max_rate_per_minute, approved_by, ticket_id, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
		scope.ID, scope.TenantID, workspaceID,
		mustMarshal(nonNil(scope.Domains)), mustMarshal(nonNil(scope.CIDRs)), mustMarshal(nonNilInts(scope.Ports)),
		string(scope.MaxRisk), scope.MaxRatePerMinute, scope.ApprovedBy, scope.TicketID, scope.ExpiresAt)
	if err != nil {
		return domain.TargetScope{}, fmt.Errorf("insert scope: %w", err)
	}
	return scope, nil
}

// scanScope decodes one row. Lists are jsonb so they never arrive as an
// unparseable PostgreSQL array literal.
func scanScope(scan func(...any) error) (domain.ScopeRecord, error) {
	var record domain.ScopeRecord
	var maxRisk string
	var domains, cidrs, ports []byte

	err := scan(&record.Scope.ID, &record.Scope.TenantID, &record.WorkspaceID,
		&domains, &cidrs, &ports, &maxRisk, &record.Scope.MaxRatePerMinute,
		&record.Scope.ApprovedBy, &record.Scope.TicketID, &record.Scope.ExpiresAt, &record.RevokedAt)
	if err != nil {
		return domain.ScopeRecord{}, err
	}

	record.Scope.MaxRisk = domain.RiskLevel(maxRisk)
	if err := decodeInto(domains, &record.Scope.Domains); err != nil {
		return domain.ScopeRecord{}, fmt.Errorf("decode scope domains: %w", err)
	}
	if err := decodeInto(cidrs, &record.Scope.CIDRs); err != nil {
		return domain.ScopeRecord{}, fmt.Errorf("decode scope cidrs: %w", err)
	}
	if err := decodeInto(ports, &record.Scope.Ports); err != nil {
		return domain.ScopeRecord{}, fmt.Errorf("decode scope ports: %w", err)
	}
	return record, nil
}

func decodeInto(raw []byte, target any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, target)
}

func nonNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nonNilInts(values []int) []int {
	if values == nil {
		return []int{}
	}
	return values
}

func (p *Postgres) GetScope(ctx context.Context, id string) (domain.ScopeRecord, error) {
	record, err := scanScope(p.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, workspace_id, domains, cidrs, ports, max_risk,
		       max_rate_per_minute, approved_by, ticket_id, expires_at, revoked_at
		FROM scopes WHERE id = $1`, id).Scan)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ScopeRecord{}, ErrScopeNotFound
	}
	if err != nil {
		return domain.ScopeRecord{}, fmt.Errorf("get scope: %w", err)
	}
	return record, nil
}

func (p *Postgres) ListScopes(ctx context.Context, workspaceID string, includeRevoked bool) ([]domain.ScopeRecord, error) {
	query := `
		SELECT id, tenant_id, workspace_id, domains, cidrs, ports, max_risk,
		       max_rate_per_minute, approved_by, ticket_id, expires_at, revoked_at
		FROM scopes WHERE workspace_id = $1`
	if !includeRevoked {
		query += ` AND revoked_at IS NULL`
	}
	query += ` ORDER BY created_at DESC`

	rows, err := p.db.QueryContext(ctx, query, workspaceID)
	if err != nil {
		return nil, fmt.Errorf("query scopes: %w", err)
	}
	defer rows.Close()

	records := make([]domain.ScopeRecord, 0)
	for rows.Next() {
		record, err := scanScope(rows.Scan)
		if err != nil {
			return nil, fmt.Errorf("scan scope: %w", err)
		}
		records = append(records, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate scopes: %w", err)
	}
	return records, nil
}
func (p *Postgres) RevokeScope(ctx context.Context, id, revokedBy string) error {
	tag, err := p.db.ExecContext(ctx, `
		UPDATE scopes SET revoked_at = now() WHERE id = $1 AND revoked_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("revoke scope: %w", err)
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return fmt.Errorf("revoke scope rows affected: %w", err)
	}
	if affected == 0 {
		return ErrScopeNotFound
	}
	// Revoking a scope must also invalidate its pending approvals, otherwise a
	// stale approval could still be used later.
	if _, err := p.db.ExecContext(ctx, `
		UPDATE scope_approvals SET decision = 'expired', decided_at = now(), reason = 'scope revoked'
		WHERE scope_id = $1 AND decision = 'pending'`, id); err != nil {
		return fmt.Errorf("expire scope approvals: %w", err)
	}
	_ = revokedBy // reserved for an audit column; recorded by the caller's audit log
	return nil
}

func (p *Postgres) RequestApproval(ctx context.Context, approval domain.Approval) (domain.Approval, bool, error) {
	if approval.ExpiresAt.IsZero() {
		approval.ExpiresAt = time.Now().Add(15 * time.Minute)
	}

	var stored domain.Approval
	var argv []byte
	var risk string
	err := p.db.QueryRowContext(ctx, `
		INSERT INTO scope_approvals (id, scope_id, target, argv, risk, decision, requested_by, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		ON CONFLICT (scope_id, target, argv) WHERE decision = 'pending' DO NOTHING
		RETURNING id, scope_id, target, argv, risk, decision, requested_by,
		          COALESCE(decided_by, ''), COALESCE(reason, ''), expires_at, created_at, decided_at`,
		approval.ID, approval.ScopeID, approval.Target, []byte(approval.Argv), string(approval.Risk),
		domain.ApprovalPending, approval.RequestedBy, approval.ExpiresAt,
	).Scan(&stored.ID, &stored.ScopeID, &stored.Target, &argv, &risk, &stored.Decision,
		&stored.RequestedBy, &stored.DecidedBy, &stored.Reason, &stored.ExpiresAt,
		&stored.CreatedAt, &stored.DecidedAt)

	if errors.Is(err, sql.ErrNoRows) {
		// An identical request is already pending; return it so the caller can
		// point at the existing approval instead of creating a duplicate.
		existing, getErr := p.pendingApproval(ctx, approval.ScopeID, approval.Target, approval.Argv)
		if getErr != nil {
			return domain.Approval{}, false, getErr
		}
		return existing, false, nil
	}
	if err != nil {
		return domain.Approval{}, false, fmt.Errorf("insert approval: %w", err)
	}
	stored.Argv = argv
	stored.Risk = domain.RiskLevel(risk)
	return stored, true, nil
}

func (p *Postgres) pendingApproval(ctx context.Context, scopeID, target string, argv json.RawMessage) (domain.Approval, error) {
	var approval domain.Approval
	var storedArgv []byte
	var risk string
	err := p.db.QueryRowContext(ctx, `
		SELECT id, scope_id, target, argv, risk, decision, requested_by,
		       COALESCE(decided_by, ''), COALESCE(reason, ''), expires_at, created_at, decided_at
		FROM scope_approvals
		WHERE scope_id = $1 AND target = $2 AND argv = $3 AND decision = 'pending'
		LIMIT 1`, scopeID, target, []byte(argv),
	).Scan(&approval.ID, &approval.ScopeID, &approval.Target, &storedArgv, &risk, &approval.Decision,
		&approval.RequestedBy, &approval.DecidedBy, &approval.Reason, &approval.ExpiresAt,
		&approval.CreatedAt, &approval.DecidedAt)
	if err != nil {
		return domain.Approval{}, fmt.Errorf("load pending approval: %w", err)
	}
	approval.Argv = storedArgv
	approval.Risk = domain.RiskLevel(risk)
	return approval, nil
}

func (p *Postgres) DecideApproval(ctx context.Context, id, decision, decidedBy, reason string) (domain.Approval, error) {
	if decision != domain.ApprovalApproved && decision != domain.ApprovalRejected {
		return domain.Approval{}, fmt.Errorf("decision must be %q or %q", domain.ApprovalApproved, domain.ApprovalRejected)
	}
	var approval domain.Approval
	var argv []byte
	var risk string
	err := p.db.QueryRowContext(ctx, `
		UPDATE scope_approvals
		SET decision = $2, decided_by = $3, reason = NULLIF($4, ''), decided_at = now()
		WHERE id = $1 AND decision = 'pending' AND expires_at > now()
		RETURNING id, scope_id, target, argv, risk, decision, requested_by,
		          COALESCE(decided_by, ''), COALESCE(reason, ''), expires_at, created_at, decided_at`,
		id, decision, decidedBy, reason,
	).Scan(&approval.ID, &approval.ScopeID, &approval.Target, &argv, &risk, &approval.Decision,
		&approval.RequestedBy, &approval.DecidedBy, &approval.Reason, &approval.ExpiresAt,
		&approval.CreatedAt, &approval.DecidedAt)
	if errors.Is(err, sql.ErrNoRows) {
		// Either it does not exist or it is no longer pending/valid. Report the
		// precise reason so a client does not retry blindly.
		existing, getErr := p.GetApproval(ctx, id)
		if getErr != nil {
			return domain.Approval{}, getErr
		}
		if existing.Decision != domain.ApprovalPending {
			return domain.Approval{}, fmt.Errorf("%w: already %s", ErrInvalidTransition, existing.Decision)
		}
		return domain.Approval{}, fmt.Errorf("%w: expired", ErrInvalidTransition)
	}
	if err != nil {
		return domain.Approval{}, fmt.Errorf("decide approval: %w", err)
	}
	approval.Argv = argv
	approval.Risk = domain.RiskLevel(risk)
	return approval, nil
}

func (p *Postgres) GetApproval(ctx context.Context, id string) (domain.Approval, error) {
	var approval domain.Approval
	var argv []byte
	var risk string
	err := p.db.QueryRowContext(ctx, `
		SELECT id, scope_id, target, argv, risk, decision, requested_by,
		       COALESCE(decided_by, ''), COALESCE(reason, ''), expires_at, created_at, decided_at
		FROM scope_approvals WHERE id = $1`, id,
	).Scan(&approval.ID, &approval.ScopeID, &approval.Target, &argv, &risk, &approval.Decision,
		&approval.RequestedBy, &approval.DecidedBy, &approval.Reason, &approval.ExpiresAt,
		&approval.CreatedAt, &approval.DecidedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Approval{}, ErrApprovalNotFound
	}
	if err != nil {
		return domain.Approval{}, fmt.Errorf("get approval: %w", err)
	}
	approval.Argv = argv
	approval.Risk = domain.RiskLevel(risk)
	return approval, nil
}

func (p *Postgres) ListApprovals(ctx context.Context, decision string, limit int) ([]domain.Approval, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	query := `
		SELECT id, scope_id, target, argv, risk, decision, requested_by,
		       COALESCE(decided_by, ''), COALESCE(reason, ''), expires_at, created_at, decided_at
		FROM scope_approvals`
	args := []any{}
	if decision != "" {
		query += ` WHERE decision = $1`
		args = append(args, decision)
	}
	query += ` ORDER BY created_at DESC LIMIT ` + fmt.Sprintf("%d", limit)

	rows, err := p.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("query approvals: %w", err)
	}
	defer rows.Close()

	approvals := make([]domain.Approval, 0)
	for rows.Next() {
		var approval domain.Approval
		var argv []byte
		var risk string
		if err := rows.Scan(&approval.ID, &approval.ScopeID, &approval.Target, &argv, &risk,
			&approval.Decision, &approval.RequestedBy, &approval.DecidedBy, &approval.Reason,
			&approval.ExpiresAt, &approval.CreatedAt, &approval.DecidedAt); err != nil {
			return nil, fmt.Errorf("scan approval: %w", err)
		}
		approval.Argv = argv
		approval.Risk = domain.RiskLevel(risk)
		approvals = append(approvals, approval)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate approvals: %w", err)
	}
	return approvals, nil
}
