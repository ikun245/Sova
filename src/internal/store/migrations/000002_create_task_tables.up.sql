CREATE TABLE agent_tasks (
    id                 text PRIMARY KEY,
    tenant_id          text NOT NULL,
    case_id            text,
    status             text NOT NULL,
    checkpoint         jsonb,
    checkpoint_version int NOT NULL DEFAULT 1,
    lease_owner        text,
    lease_until        timestamptz,
    attempt            int NOT NULL DEFAULT 0,
    created_at         timestamptz NOT NULL DEFAULT now(),
    updated_at         timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX agent_tasks_tenant_status ON agent_tasks (tenant_id, status);
CREATE INDEX agent_tasks_expired_lease ON agent_tasks (lease_until) WHERE lease_until IS NOT NULL;

CREATE TABLE task_intents (
    id         text PRIMARY KEY,
    task_id    text NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    seq        int NOT NULL,
    kind       text NOT NULL,
    payload    jsonb NOT NULL,
    depends_on jsonb NOT NULL DEFAULT '[]'::jsonb,
    status     text NOT NULL,
    claimed_by text,
    result_ref text,
    UNIQUE (task_id, seq)
);

CREATE INDEX task_intents_pending ON task_intents (task_id, seq) WHERE status = 'pending';

CREATE TABLE task_events (
    id             bigserial PRIMARY KEY,
    task_id        text NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    seq            int NOT NULL,
    kind           text NOT NULL,
    schema_version int NOT NULL DEFAULT 1,
    payload        jsonb NOT NULL,
    at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (task_id, seq)
);

CREATE TABLE session_events (
    id             bigserial PRIMARY KEY,
    run_id         text NOT NULL,
    seq            int NOT NULL,
    kind           text NOT NULL,
    schema_version int NOT NULL DEFAULT 1,
    payload        jsonb NOT NULL,
    at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (run_id, seq)
);