-- One-shot approvals: an approval authorizes exactly one call. Without a
-- consumed marker, an "approved" row could be replayed for every later command
-- against the same target, which defeats the point of asking a human.
ALTER TABLE scope_approvals ADD COLUMN used_at timestamptz;

-- Only one approval may be consumed per (scope, target, argv) is NOT what we
-- want; instead we ensure a consumed row can never be consumed twice, which the
-- conditional UPDATE in ConsumeApproval enforces. This index keeps the
-- "usable approvals" lookup cheap.
CREATE INDEX scope_approvals_approved_unused
    ON scope_approvals (scope_id, target)
    WHERE decision = 'approved' AND used_at IS NULL;