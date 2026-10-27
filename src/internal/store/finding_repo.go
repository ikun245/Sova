package store

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"soc/agent/internal/domain"
)

// ErrFindingNotFound reports a rejected finding id that does not exist.
var ErrFindingNotFound = errors.New("finding not found")

// CreateFinding inserts a finding unless the task already has one with the same
// dedup key.
//
// ON CONFLICT DO NOTHING plus a follow-up read is chosen over "select then
// insert" because two workers finishing at the same moment would otherwise both
// pass the check and one insert would fail. Here both callers succeed, and the
// second learns created=false.
func (p *Postgres) CreateFinding(ctx context.Context, finding domain.Finding) (domain.Finding, bool, error) {
	if err := finding.Validate(); err != nil {
		return domain.Finding{}, false, err
	}
	if finding.ID == "" {
		finding.ID = "finding-" + randomSuffix()
	}
	if finding.DedupKey == "" {
		finding.DedupKey = finding.NormalizedDedupKey()
	}
	if finding.CreatedAt.IsZero() {
		finding.CreatedAt = time.Now()
	}

	evidence, err := json.Marshal(finding.Evidence)
	if err != nil {
		return domain.Finding{}, false, fmt.Errorf("encode finding evidence: %w", err)
	}

	tag, err := p.db.ExecContext(ctx, `
		INSERT INTO findings (id, task_id, agent_key, duty, kind, target, claim,
		                      evidence, confidence, dedup_key, rejected, reject_note, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, NULLIF($12, ''), $13)
		ON CONFLICT (task_id, dedup_key) DO NOTHING`,
		finding.ID, finding.TaskID, finding.AgentKey, finding.Duty, finding.Kind,
		finding.Target, finding.Claim, evidence, finding.Confidence, finding.DedupKey,
		finding.Rejected, finding.RejectNote, finding.CreatedAt)
	if err != nil {
		return domain.Finding{}, false, fmt.Errorf("insert finding: %w", err)
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return domain.Finding{}, false, fmt.Errorf("insert finding rows affected: %w", err)
	}
	if affected > 0 {
		return finding, true, nil
	}

	// A conflict means the fact is already known. Return the stored row so the
	// caller reports the original agent rather than inventing a new provenance.
	existing, err := p.findingByDedupKey(ctx, finding.TaskID, finding.DedupKey)
	if err != nil {
		return domain.Finding{}, false, err
	}
	return existing, false, nil
}

func (p *Postgres) findingByDedupKey(ctx context.Context, taskID, dedupKey string) (domain.Finding, error) {
	row := p.db.QueryRowContext(ctx, `
		SELECT id, task_id, agent_key, duty, kind, target, claim, evidence,
		       confidence, dedup_key, rejected, COALESCE(reject_note, ''), created_at
		FROM findings WHERE task_id = $1 AND dedup_key = $2`, taskID, dedupKey)
	finding, err := scanFinding(row)
	if errors.Is(err, ErrFindingNotFound) {
		return domain.Finding{}, fmt.Errorf("finding conflict but stored row is missing")
	}
	return finding, err
}

// ListFindings returns every finding for a task in creation order. Rejected
// rows are included: the report must be able to say what was dismissed.
func (p *Postgres) ListFindings(ctx context.Context, taskID string) ([]domain.Finding, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, task_id, agent_key, duty, kind, target, claim, evidence,
		       confidence, dedup_key, rejected, COALESCE(reject_note, ''), created_at
		FROM findings WHERE task_id = $1 ORDER BY created_at, id`, taskID)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()

	out := make([]domain.Finding, 0, 8)
	for rows.Next() {
		finding, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	return out, nil
}

// RejectFinding records that the critic refused a claim. The row stays so the
// trail shows the attempt, and a retry with better evidence produces a new row
// because the claim will differ.
func (p *Postgres) RejectFinding(ctx context.Context, findingID, reason string) error {
	tag, err := p.db.ExecContext(ctx, `
		UPDATE findings SET rejected = true, reject_note = $2
		WHERE id = $1 AND rejected = false`, findingID, reason)
	if err != nil {
		return fmt.Errorf("reject finding: %w", err)
	}
	affected, err := tag.RowsAffected()
	if err != nil {
		return fmt.Errorf("reject finding rows affected: %w", err)
	}
	if affected == 0 {
		return ErrFindingNotFound
	}
	return nil
}

// rowScanner is the shared shape of *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

// randomSuffix makes an id that does not collide across workers. It does not
// need to be unguessable, only unique.
func randomSuffix() string {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		// Falling back to the clock keeps the caller working; a duplicate id
		// would surface as a primary-key error rather than silent corruption.
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return hex.EncodeToString(buf)
}

func scanFinding(scanner rowScanner) (domain.Finding, error) {
	var finding domain.Finding
	var evidence []byte
	err := scanner.Scan(&finding.ID, &finding.TaskID, &finding.AgentKey, &finding.Duty,
		&finding.Kind, &finding.Target, &finding.Claim, &evidence, &finding.Confidence,
		&finding.DedupKey, &finding.Rejected, &finding.RejectNote, &finding.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Finding{}, ErrFindingNotFound
	}
	if err != nil {
		return domain.Finding{}, fmt.Errorf("scan finding: %w", err)
	}
	if err := json.Unmarshal(evidence, &finding.Evidence); err != nil {
		return domain.Finding{}, fmt.Errorf("decode finding evidence: %w", err)
	}
	return finding, nil
}
