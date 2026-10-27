CREATE TABLE queue_outbox (
    id           bigserial PRIMARY KEY,
    topic        text NOT NULL,
    payload      jsonb NOT NULL,
    available_at timestamptz NOT NULL DEFAULT now(),
    published_at timestamptz,
    attempts     int NOT NULL DEFAULT 0,
    last_error   text,
    created_at   timestamptz NOT NULL DEFAULT now()
);

-- The relay only scans unpublished rows; a partial index keeps that scan cheap.
CREATE INDEX queue_outbox_unpublished ON queue_outbox (available_at) WHERE published_at IS NULL;