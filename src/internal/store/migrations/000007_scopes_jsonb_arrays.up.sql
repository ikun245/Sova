-- Scope lists were created as Postgres arrays, but the Go repository decodes
-- them as JSON documents. With database/sql + pgx stdlib a text[] arrives as the
-- literal "{example.com}", which json.Unmarshal cannot read, so every scope read
-- failed. jsonb matches the shape the code already expects and the shape every
-- other list column in this schema uses (argv, depends_on, reasons).
--
-- The array default is dropped first: Postgres cannot cast a text[] default to
-- jsonb automatically and fails the whole ALTER otherwise. It is restored as a
-- JSON array, not '{}', because the Go side unmarshals into []string and an
-- empty JSON object is not a valid array.
ALTER TABLE scopes
    ALTER COLUMN domains DROP DEFAULT,
    ALTER COLUMN cidrs   DROP DEFAULT,
    ALTER COLUMN ports   DROP DEFAULT;

ALTER TABLE scopes
    ALTER COLUMN domains TYPE jsonb USING to_jsonb(domains),
    ALTER COLUMN cidrs   TYPE jsonb USING to_jsonb(cidrs),
    ALTER COLUMN ports   TYPE jsonb USING to_jsonb(ports);

ALTER TABLE scopes
    ALTER COLUMN domains SET DEFAULT '[]'::jsonb,
    ALTER COLUMN cidrs   SET DEFAULT '[]'::jsonb,
    ALTER COLUMN ports   SET DEFAULT '[]'::jsonb;
