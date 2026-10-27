package domain

// LeaseState explains why a lease renewal failed. It exists so an operator can
// tell "another worker legitimately took over after a crash" from "this worker
// lost the race for a reason that indicates a bug".
type LeaseState string

const (
	// LeaseOK means the caller still owns the intent. Present so a diagnostic
	// path that races with a successful renewal cannot return an empty value.
	LeaseOK LeaseState = "ok"
	// LeaseIntentNotFound means the intent id does not exist. This is a caller
	// bug, not contention: it should be reported, not retried.
	LeaseIntentNotFound LeaseState = "intent_not_found"
	// LeaseIntentNotClaimed means the intent is no longer claimed. Either it was
	// completed already, or it was returned to pending after the lease lapsed.
	LeaseIntentNotClaimed LeaseState = "intent_not_claimed"
	// LeaseClaimedByOther means a different worker now owns the intent.
	LeaseClaimedByOther LeaseState = "claimed_by_other"
	// LeaseExpired means this worker still owns the intent but its lease has
	// lapsed. Distinct from contention because the recovery is different: nobody
	// has taken over yet, so the work will be redispatched rather than lost.
	LeaseExpired LeaseState = "expired"
	// LeaseTaskOwnerChanged means the intent still names this worker but the
	// task lease was reassigned. Treat it as lost: whoever holds the task lease
	// makes the scheduling decisions.
	LeaseTaskOwnerChanged LeaseState = "task_owner_changed"
	// LeaseTaskFinished means the task reached a terminal status. Completing
	// work here would resurrect a finished task, so the caller must stop.
	LeaseTaskFinished LeaseState = "task_finished"
)

// Lost reports whether the state means the caller no longer holds the lease.
// Only LeaseOK is recoverable; every other value requires stopping.
func (s LeaseState) Lost() bool { return s != LeaseOK }
