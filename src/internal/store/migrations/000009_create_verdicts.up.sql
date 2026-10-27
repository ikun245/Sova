-- Verdicts are kept separately from agent_tasks.checkpoint. The checkpoint is
-- overwritten by the next intent, so there is no way to list or filter past
-- conclusions once a task keeps running; this table is the queryable history.
CREATE TABLE verdicts (
    id         bigserial PRIMARY KEY,
    task_id    text NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    intent_id  text NOT NULL,
    verdict    text NOT NULL,
    severity   text NOT NULL,
    confidence double precision NOT NULL,
    payload    jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX verdicts_task_created ON verdicts (task_id, created_at);
