CREATE TABLE workspaces (
    id         text PRIMARY KEY,
    tenant_id  text NOT NULL,
    name       text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX workspaces_tenant ON workspaces (tenant_id);

CREATE TABLE teams (
    id           text PRIMARY KEY,
    workspace_id text NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    name         text NOT NULL,
    kind         text NOT NULL, -- blue / red / qa / custom
    created_at   timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX teams_workspace ON teams (workspace_id);

CREATE TABLE team_members (
    id           text PRIMARY KEY,
    team_id      text NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    agent_key    text NOT NULL,
    duty         text NOT NULL, -- triage / hunting / intel / critic / reporter
    model_role   text NOT NULL, -- resolves through the model role binding
    turn_budget  int NOT NULL DEFAULT 1024,
    enabled      boolean NOT NULL DEFAULT true,
    position     int NOT NULL DEFAULT 0,
    UNIQUE (team_id, agent_key)
);

CREATE INDEX team_members_team ON team_members (team_id, position);

CREATE TABLE rooms (
    id           text PRIMARY KEY,
    workspace_id text NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    team_id      text REFERENCES teams(id) ON DELETE SET NULL,
    task_id      text,
    topic        text NOT NULL,
    trigger      text NOT NULL, -- user / stall / agent_request
    status       text NOT NULL, -- open / summoning / deciding / closed / escalated
    budget       jsonb NOT NULL DEFAULT '{}'::jsonb,
    decision     jsonb,
    opened_by    text NOT NULL,
    created_at   timestamptz NOT NULL DEFAULT now(),
    closed_at    timestamptz
);

CREATE INDEX rooms_workspace_status ON rooms (workspace_id, status);
CREATE INDEX rooms_task ON rooms (task_id) WHERE task_id IS NOT NULL;

CREATE TABLE room_participants (
    room_id     text NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    agent_key   text NOT NULL,
    duty        text NOT NULL,
    model_role  text NOT NULL,
    state       text NOT NULL DEFAULT 'invited', -- invited / spoke / skipped
    tokens_used int NOT NULL DEFAULT 0,
    PRIMARY KEY (room_id, agent_key)
);

-- Append-only room transcript. seq is monotonic per room so a resuming
-- consumer can detect gaps rather than silently skipping history.
CREATE TABLE room_events (
    id             bigserial PRIMARY KEY,
    room_id        text NOT NULL REFERENCES rooms(id) ON DELETE CASCADE,
    seq            int NOT NULL,
    kind           text NOT NULL,
    actor          text NOT NULL,
    schema_version int NOT NULL DEFAULT 1,
    payload        jsonb NOT NULL,
    at             timestamptz NOT NULL DEFAULT now(),
    UNIQUE (room_id, seq)
);

CREATE INDEX room_events_room ON room_events (room_id, seq);

-- One escalation per (task, reason bucket) keeps a stuck agent from opening a
-- new room on every retry.
CREATE TABLE escalations (
    id          text PRIMARY KEY,
    task_id     text NOT NULL,
    room_id     text REFERENCES rooms(id) ON DELETE SET NULL,
    trigger     text NOT NULL,
    reasons     jsonb NOT NULL,
    signals     jsonb NOT NULL,
    status      text NOT NULL DEFAULT 'open', -- open / in_room / resolved / rejected
    created_at  timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz
);

CREATE UNIQUE INDEX escalations_open_per_task ON escalations (task_id) WHERE status IN ('open', 'in_room');
CREATE INDEX escalations_task ON escalations (task_id);