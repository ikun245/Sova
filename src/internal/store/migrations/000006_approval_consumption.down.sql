DROP INDEX IF EXISTS scope_approvals_approved_unused;
ALTER TABLE scope_approvals DROP COLUMN IF EXISTS used_at;