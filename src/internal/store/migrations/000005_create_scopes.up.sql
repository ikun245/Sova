CREATE TABLE scopes (
    id                  text PRIMARY KEY,
    tenant_id           text NOT NULL,
    workspace_id        text NOT NULL,
    domains             text[] NOT NULL DEFAULT '{}',
    cidrs               text[] NOT NULL DEFAULT '{}',
    ports               int[] NOT NULL DEFAULT '{}',
    max_risk            text NOT NULL,
    max_rate_per_minute int NOT NULL DEFAULT 0,
    approved_by         text NOT NULL,
    ticket_id           text NOT NULL,
    expires_at          timestamptz NOT NULL,
    created_at          timestamptz NOT NULL DEFAULT now(),
    revoked_at          timestamptz
);

CREATE INDEX scopes_workspace ON scopes (workspace_id, created_at DESC);
CREATE INDEX scopes_active ON scopes (workspace_id) WHERE revoked_at IS NULL;

-- One approval per (scope, target, argv) while pending, so a retrying agent
-- cannot flood the human queue with duplicates of the same request.
CREATE TABLE scope_approvals (
    id           text PRIMARY KEY,
    scope_id     text NOT NULL REFERENCES scopes(id) ON DELETE CASCADE,
    target       text NOT NULL,
    argv         jsonb NOT NULL,
    risk         text NOT NULL,
    decision     text NOT NULL DEFAULT 'pending', -- pending / approved / rejected / expired
    requested_by text NOT NULL,
    decided_by   text,
    reason       text,
    expires_at   timestamptz NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    decided_at   timestamptz
);

CREATE UNIQUE INDEX scope_approvals_pending
    ON scope_approvals (scope_id, target, argv)
    WHERE decision = 'pending';
CREATE INDEX scope_approvals_pending_list ON scope_approvals (decision, created_at);