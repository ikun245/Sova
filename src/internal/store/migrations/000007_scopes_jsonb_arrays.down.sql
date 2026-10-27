-- Reverse through temporary columns: ALTER COLUMN ... TYPE ... USING does not
-- accept the subquery needed to turn a jsonb array back into a Postgres array,
-- while UPDATE does.
ALTER TABLE scopes
    ALTER COLUMN domains DROP DEFAULT,
    ALTER COLUMN cidrs   DROP DEFAULT,
    ALTER COLUMN ports   DROP DEFAULT;

ALTER TABLE scopes ADD COLUMN domains_arr text[] NOT NULL DEFAULT '{}';
UPDATE scopes SET domains_arr = ARRAY(SELECT jsonb_array_elements_text(domains));
ALTER TABLE scopes DROP COLUMN domains;
ALTER TABLE scopes RENAME COLUMN domains_arr TO domains;

ALTER TABLE scopes ADD COLUMN cidrs_arr text[] NOT NULL DEFAULT '{}';
UPDATE scopes SET cidrs_arr = ARRAY(SELECT jsonb_array_elements_text(cidrs));
ALTER TABLE scopes DROP COLUMN cidrs;
ALTER TABLE scopes RENAME COLUMN cidrs_arr TO cidrs;

ALTER TABLE scopes ADD COLUMN ports_arr int[] NOT NULL DEFAULT '{}';
UPDATE scopes SET ports_arr = ARRAY(SELECT jsonb_array_elements_text(ports)::int);
ALTER TABLE scopes DROP COLUMN ports;
ALTER TABLE scopes RENAME COLUMN ports_arr TO ports;
