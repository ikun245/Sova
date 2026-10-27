CREATE TABLE alerts (
    id text PRIMARY KEY,
    tenant_id text NOT NULL,
    source text NOT NULL,
    raw jsonb NOT NULL,
    normalized jsonb NOT NULL DEFAULT '{}'::jsonb,
    dedup_key text NOT NULL,
    status text NOT NULL DEFAULT 'received',
    received_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX alerts_tenant_dedup_key ON alerts (tenant_id, dedup_key);
CREATE INDEX alerts_tenant_received_at ON alerts (tenant_id, received_at DESC);