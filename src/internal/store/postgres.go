package store

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	"github.com/golang-migrate/migrate/v4/source/iofs"
	"soc/agent/internal/domain"

	_ "github.com/jackc/pgx/v5/stdlib"
)

//go:embed migrations/*.sql
var migrationFiles embed.FS

type Postgres struct {
	db  *sql.DB
	dsn string
}

func OpenPostgres(ctx context.Context, dsn string) (*Postgres, error) {
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL pool: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping PostgreSQL: %w", err)
	}
	return &Postgres{db: db, dsn: dsn}, nil
}

func (p *Postgres) Close() error {
	return p.db.Close()
}

func (p *Postgres) Ping(ctx context.Context) error {
	return p.db.PingContext(ctx)
}

func (p *Postgres) Migrate() error {
	source, err := iofs.New(migrationFiles, "migrations")
	if err != nil {
		return fmt.Errorf("open embedded migrations: %w", err)
	}

	// The postgres driver closes the *sql.DB it is given, so migrations must use
	// a dedicated pool; otherwise the API's pool would be closed after startup.
	migrationDB, err := sql.Open("pgx", p.dsn)
	if err != nil {
		return fmt.Errorf("open migration pool: %w", err)
	}
	defer migrationDB.Close()

	databaseDriver, err := postgres.WithInstance(migrationDB, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("create migration database driver: %w", err)
	}
	engine, err := migrate.NewWithInstance("iofs", source, "postgres", databaseDriver)
	if err != nil {
		return fmt.Errorf("create migration engine: %w", err)
	}
	if err := engine.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
		return fmt.Errorf("apply migrations: %w", err)
	}
	return nil
}

func (p *Postgres) CreateAlert(ctx context.Context, alert domain.Alert) (domain.Alert, error) {
	// A duplicate alert is not a new event: return the existing row so callers
	// can distinguish "created" from "deduplicated" by the returned ID.
	const query = `
		INSERT INTO alerts (id, tenant_id, source, raw, dedup_key, status)
		VALUES ($1, $2, $3, $4, $5, $6)
		ON CONFLICT (tenant_id, dedup_key) DO UPDATE SET dedup_key = alerts.dedup_key
		RETURNING id, tenant_id, source, raw, dedup_key, status, received_at`
	err := p.db.QueryRowContext(ctx, query,
		alert.ID, alert.TenantID, alert.Source, []byte(alert.Raw), alert.DedupKey, alert.Status,
	).Scan(&alert.ID, &alert.TenantID, &alert.Source, &alert.Raw, &alert.DedupKey, &alert.Status, &alert.ReceivedAt)
	if err != nil {
		return domain.Alert{}, fmt.Errorf("insert alert: %w", err)
	}
	return alert, nil
}

func (p *Postgres) ListAlerts(ctx context.Context, tenantID string, limit int) ([]domain.Alert, error) {
	rows, err := p.db.QueryContext(ctx, `
		SELECT id, tenant_id, source, raw, dedup_key, status, received_at
		FROM alerts WHERE tenant_id = $1 ORDER BY received_at DESC LIMIT $2`, tenantID, limit)
	if err != nil {
		return nil, fmt.Errorf("query alerts: %w", err)
	}
	defer rows.Close()

	alerts := make([]domain.Alert, 0)
	for rows.Next() {
		var alert domain.Alert
		if err := rows.Scan(&alert.ID, &alert.TenantID, &alert.Source, &alert.Raw, &alert.DedupKey, &alert.Status, &alert.ReceivedAt); err != nil {
			return nil, fmt.Errorf("scan alert: %w", err)
		}
		alerts = append(alerts, alert)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate alerts: %w", err)
	}
	return alerts, nil
}
