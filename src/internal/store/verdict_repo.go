package store

import (
	"context"
	"fmt"

	"soc/agent/internal/domain"
)

// CreateVerdict inserts one triage conclusion. Called alongside (not instead
// of) the checkpoint write, so a resumed task still finds its latest verdict in
// the checkpoint even if this table is unavailable.
func (p *Postgres) CreateVerdict(ctx context.Context, record domain.VerdictRecord) error {
	_, err := p.db.ExecContext(ctx, `
		INSERT INTO verdicts (task_id, intent_id, verdict, severity, confidence, payload)
		VALUES ($1, $2, $3, $4, $5, $6)`,
		record.TaskID, record.IntentID, record.Verdict, record.Severity, record.Confidence, []byte(record.Payload))
	if err != nil {
		return fmt.Errorf("insert verdict: %w", err)
	}
	return nil
}

// ListVerdicts returns every verdict for a task, oldest first, so a caller can
// see how a judgement changed across attempts.
func (p *Postgres) ListVerdicts(ctx context.Context, taskID string) ([]domain.VerdictRecord, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT task_id, intent_id, verdict, severity, confidence, payload, created_at
		FROM verdicts WHERE task_id = $1 ORDER BY created_at, id`, taskID)
	if err != nil {
		return nil, fmt.Errorf("list verdicts: %w", err)
	}
	defer rows.Close()

	out := make([]domain.VerdictRecord, 0, 4)
	for rows.Next() {
		var record domain.VerdictRecord
		var payload []byte
		if err := rows.Scan(&record.TaskID, &record.IntentID, &record.Verdict,
			&record.Severity, &record.Confidence, &payload, &record.CreatedAt); err != nil {
			return nil, fmt.Errorf("scan verdict: %w", err)
		}
		record.Payload = payload
		out = append(out, record)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list verdicts: %w", err)
	}
	return out, nil
}
