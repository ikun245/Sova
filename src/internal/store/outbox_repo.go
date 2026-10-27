package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"soc/agent/internal/domain"
)

func (p *Postgres) IngestAlert(ctx context.Context, alert domain.Alert, task domain.Task, intents []domain.Intent, message domain.OutboxMessage) (domain.Alert, bool, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return domain.Alert{}, false, fmt.Errorf("begin ingest transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	// Insert only if the dedup key is new. RETURNING yields no row when the
	// alert already exists, which is how we distinguish created from duplicate.
	var stored domain.Alert
	err = tx.QueryRowContext(ctx, `
		INSERT INTO alerts (id, tenant_id, source, raw, dedup_key, status)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, dedup_key) DO NOTHING
		RETURNING id, tenant_id, source, raw, dedup_key, status, received_at`,
		alert.ID, alert.TenantID, alert.Source, []byte(alert.Raw), alert.DedupKey, alert.Status,
	).Scan(&stored.ID, &stored.TenantID, &stored.Source, &stored.Raw, &stored.DedupKey,
		&stored.Status, &stored.ReceivedAt)

	if errors.Is(err, sql.ErrNoRows) {
		// Duplicate: return the existing alert without enqueueing more work.
		existing, err := p.alertByDedupKey(ctx, tx, alert.TenantID, alert.DedupKey)
		if err != nil {
			return domain.Alert{}, false, err
		}
		if err := tx.Commit(); err != nil {
			return domain.Alert{}, false, fmt.Errorf("commit ingest transaction: %w", err)
		}
		return existing, false, nil
	}
	if err != nil {
		return domain.Alert{}, false, fmt.Errorf("insert alert: %w", err)
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO agent_tasks (id, tenant_id, case_id, status)
		VALUES ($1, $2, NULLIF($3, ''), $4)`,
		task.ID, task.TenantID, task.CaseID, task.Status,
	); err != nil {
		return domain.Alert{}, false, fmt.Errorf("insert task: %w", err)
	}

	for _, intent := range intents {
		dependsOn := intent.DependsOn
		if dependsOn == nil {
			dependsOn = []string{}
		}
		encoded, err := json.Marshal(dependsOn)
		if err != nil {
			return domain.Alert{}, false, fmt.Errorf("encode intent dependencies: %w", err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO task_intents (id, task_id, seq, kind, payload, depends_on, status)
			VALUES ($1, $2, $3, $4, $5, $6, $7)`,
			intent.ID, task.ID, intent.Seq, intent.Kind, []byte(intent.Payload), encoded, intent.Status,
		); err != nil {
			return domain.Alert{}, false, fmt.Errorf("insert intent %d: %w", intent.Seq, err)
		}
	}

	if _, err := tx.ExecContext(ctx, `
		INSERT INTO queue_outbox (topic, payload) VALUES ($1, $2)`,
		message.Topic, []byte(message.Payload),
	); err != nil {
		return domain.Alert{}, false, fmt.Errorf("insert outbox message: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return domain.Alert{}, false, fmt.Errorf("commit ingest transaction: %w", err)
	}
	return stored, true, nil
}

func (p *Postgres) alertByDedupKey(ctx context.Context, tx *sql.Tx, tenantID, dedupKey string) (domain.Alert, error) {
	var alert domain.Alert
	err := tx.QueryRowContext(ctx, `
		SELECT id, tenant_id, source, raw, dedup_key, status, received_at
		FROM alerts WHERE tenant_id = $1 AND dedup_key = $2`, tenantID, dedupKey,
	).Scan(&alert.ID, &alert.TenantID, &alert.Source, &alert.Raw, &alert.DedupKey,
		&alert.Status, &alert.ReceivedAt)
	if err != nil {
		return domain.Alert{}, fmt.Errorf("load duplicate alert: %w", err)
	}
	return alert, nil
}

func (p *Postgres) PublishPending(ctx context.Context, limit int) ([]domain.OutboxItem, error) {
	tx, err := p.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, fmt.Errorf("begin outbox transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()

	rows, err := tx.QueryContext(ctx, `
		SELECT id, topic, payload, attempts
		FROM queue_outbox
		WHERE published_at IS NULL AND available_at <= now()
		ORDER BY id
		LIMIT $1
		FOR UPDATE SKIP LOCKED`, limit)
	if err != nil {
		return nil, fmt.Errorf("select outbox messages: %w", err)
	}

	items := make([]domain.OutboxItem, 0, limit)
	for rows.Next() {
		var item domain.OutboxItem
		var payload []byte
		if err := rows.Scan(&item.ID, &item.Topic, &payload, &item.Attempts); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan outbox message: %w", err)
		}
		item.Payload = payload
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, fmt.Errorf("iterate outbox messages: %w", err)
	}
	rows.Close()

	// Commit while still holding the row locks is not possible, but releasing
	// them immediately is safe because the relay treats this batch as in-flight
	// until MarkPublished/MarkFailed runs.
	if err := tx.Commit(); err != nil {
		return nil, fmt.Errorf("commit outbox transaction: %w", err)
	}
	return items, nil
}

func (p *Postgres) MarkPublished(ctx context.Context, ids []int64) error {
	if len(ids) == 0 {
		return nil
	}
	_, err := p.db.ExecContext(ctx, `
		UPDATE queue_outbox SET published_at = now() WHERE id = ANY($1)`, ids)
	if err != nil {
		return fmt.Errorf("mark outbox published: %w", err)
	}
	return nil
}

func (p *Postgres) MarkFailed(ctx context.Context, id int64, reason string) error {
	// Exponential-ish backoff keeps a persistently failing message from
	// spinning while still retrying it later.
	_, err := p.db.ExecContext(ctx, `
		UPDATE queue_outbox
		SET attempts = attempts + 1,
		    last_error = $2,
		    available_at = now() + (interval '5 seconds' * LEAST(attempts + 1, 12))
		WHERE id = $1`, id, reason)
	if err != nil {
		return fmt.Errorf("mark outbox failed: %w", err)
	}
	return nil
}
