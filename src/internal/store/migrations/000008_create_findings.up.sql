-- Findings are the only cross-agent handoff: a worker's conversation does not
-- propagate, only its distilled claims and the evidence for them.
CREATE TABLE findings (
    id          text PRIMARY KEY,
    task_id     text NOT NULL REFERENCES agent_tasks(id) ON DELETE CASCADE,
    agent_key   text NOT NULL,
    duty        text NOT NULL,
    kind        text NOT NULL, -- recon / exposure / access / negative
    target      text NOT NULL DEFAULT '',
    claim       text NOT NULL,
    evidence    jsonb NOT NULL DEFAULT '[]'::jsonb,
    confidence  double precision NOT NULL DEFAULT 0,
    dedup_key   text NOT NULL,
    rejected    boolean NOT NULL DEFAULT false,
    reject_note text,
    created_at  timestamptz NOT NULL DEFAULT now()
);

-- Two agents confirming the same fact must converge on one row. The unique
-- index is what makes that true under concurrency; an application-level
-- "select then insert" would leave a race where both claim to be first.
CREATE UNIQUE INDEX findings_task_dedup ON findings (task_id, dedup_key);
CREATE INDEX findings_task_created ON findings (task_id, created_at);
CREATE INDEX findings_task_kind ON findings (task_id, kind);
