//go:build integration

package store

import (
	"context"
	"encoding/json"
	"sync"
	"testing"
	"time"

	"soc/agent/internal/domain"
)

// approvedCall creates an approved approval bound to one exact command.
func approvedCall(t *testing.T, database *Postgres, scope domain.TargetScope, argv []string) domain.Approval {
	t.Helper()
	ctx := context.Background()
	approval, _, err := database.RequestApproval(ctx, domain.Approval{
		ID:          "ap-" + scope.ID,
		ScopeID:     scope.ID,
		Target:      "example.com:443",
		Argv:        domain.NormalizeArgv(argv),
		Risk:        domain.RiskActive,
		RequestedBy: "worker",
		ExpiresAt:   time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("RequestApproval() error = %v", err)
	}
	if _, err := database.DecideApproval(ctx, approval.ID, domain.ApprovalApproved, "analyst", "ok"); err != nil {
		t.Fatalf("DecideApproval() error = %v", err)
	}
	return approval
}

func TestConsumeApprovalSucceedsOnce(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	workspaceID := newWorkspace(t, database)
	scope := newTestScope(t, database, workspaceID)
	argv := []string{"nmap", "-sV", "example.com"}
	approval := approvedCall(t, database, scope, argv)

	consumed, err := database.ConsumeApproval(ctx, domain.ApprovalCheck{
		ApprovalID: approval.ID,
		ScopeID:    scope.ID,
		Target:     "example.com:443",
		Argv:       domain.NormalizeArgv(argv),
	})
	if err != nil {
		t.Fatalf("ConsumeApproval() error = %v", err)
	}
	if consumed.ID != approval.ID {
		t.Fatalf("consumed %q, want %q", consumed.ID, approval.ID)
	}

	// One approval authorizes one call.
	_, err = database.ConsumeApproval(ctx, domain.ApprovalCheck{
		ApprovalID: approval.ID,
		ScopeID:    scope.ID,
		Target:     "example.com:443",
		Argv:       domain.NormalizeArgv(argv),
	})
	if domain.AsToolError(err).Code != domain.CodeApprovalConsumed {
		t.Fatalf("second consume code = %q, want approval_consumed", domain.AsToolError(err).Code)
	}
}

func TestConsumeApprovalIsAtomicUnderConcurrency(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	workspaceID := newWorkspace(t, database)
	scope := newTestScope(t, database, workspaceID)
	argv := []string{"nmap", "-sV", "example.com"}
	approval := approvedCall(t, database, scope, argv)

	const workers = 8
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := database.ConsumeApproval(ctx, domain.ApprovalCheck{
				ApprovalID: approval.ID,
				ScopeID:    scope.ID,
				Target:     "example.com:443",
				Argv:       domain.NormalizeArgv(argv),
			})
			if err == nil {
				mu.Lock()
				successes++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	if successes != 1 {
		t.Fatalf("successful consumes = %d, want exactly 1", successes)
	}
}

func TestConsumeApprovalRejectsMismatchedTarget(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	workspaceID := newWorkspace(t, database)
	scope := newTestScope(t, database, workspaceID)
	argv := []string{"nmap", "-sV", "example.com"}
	approval := approvedCall(t, database, scope, argv)

	_, err := database.ConsumeApproval(ctx, domain.ApprovalCheck{
		ApprovalID: approval.ID,
		ScopeID:    scope.ID,
		Target:     "internal.example:443",
		Argv:       domain.NormalizeArgv(argv),
	})
	if domain.AsToolError(err).Code != domain.CodeApprovalMismatch {
		t.Fatalf("code = %q, want approval_mismatch", domain.AsToolError(err).Code)
	}

	// The approval must still be usable for the target it was granted for.
	if _, err := database.ConsumeApproval(ctx, domain.ApprovalCheck{
		ApprovalID: approval.ID,
		ScopeID:    scope.ID,
		Target:     "example.com:443",
		Argv:       domain.NormalizeArgv(argv),
	}); err != nil {
		t.Fatalf("the original binding should still work: %v", err)
	}
}

func TestConsumeApprovalRejectsMismatchedArgv(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	workspaceID := newWorkspace(t, database)
	scope := newTestScope(t, database, workspaceID)
	approval := approvedCall(t, database, scope, []string{"nmap", "-sV", "example.com"})

	// A human approved a service scan; a full port scan is a different action.
	_, err := database.ConsumeApproval(ctx, domain.ApprovalCheck{
		ApprovalID: approval.ID,
		ScopeID:    scope.ID,
		Target:     "example.com:443",
		Argv:       domain.NormalizeArgv([]string{"nmap", "-p-", "example.com"}),
	})
	if domain.AsToolError(err).Code != domain.CodeApprovalMismatch {
		t.Fatalf("code = %q, want approval_mismatch", domain.AsToolError(err).Code)
	}
}

func TestConsumeApprovalRejectsPendingAndRejected(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	workspaceID := newWorkspace(t, database)
	scope := newTestScope(t, database, workspaceID)
	argv := []string{"nmap", "example.com"}

	pending, _, err := database.RequestApproval(ctx, domain.Approval{
		ID: "ap-pending-" + scope.ID, ScopeID: scope.ID, Target: "example.com:443",
		Argv: domain.NormalizeArgv(argv), Risk: domain.RiskActive, RequestedBy: "worker",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("RequestApproval() error = %v", err)
	}

	_, err = database.ConsumeApproval(ctx, domain.ApprovalCheck{
		ApprovalID: pending.ID, ScopeID: scope.ID, Target: "example.com:443",
		Argv: domain.NormalizeArgv(argv),
	})
	if domain.AsToolError(err).Code != domain.CodeApprovalRequired {
		t.Fatalf("pending code = %q, want approval_required", domain.AsToolError(err).Code)
	}

	if _, err := database.DecideApproval(ctx, pending.ID, domain.ApprovalRejected, "analyst", "too risky"); err != nil {
		t.Fatalf("DecideApproval() error = %v", err)
	}
	_, err = database.ConsumeApproval(ctx, domain.ApprovalCheck{
		ApprovalID: pending.ID, ScopeID: scope.ID, Target: "example.com:443",
		Argv: domain.NormalizeArgv(argv),
	})
	if domain.AsToolError(err).Code != domain.CodeApprovalRejected {
		t.Fatalf("rejected code = %q, want approval_rejected", domain.AsToolError(err).Code)
	}
}

func TestConsumeApprovalRejectsUnknownAndExpired(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	workspaceID := newWorkspace(t, database)
	scope := newTestScope(t, database, workspaceID)

	if _, err := database.ConsumeApproval(ctx, domain.ApprovalCheck{
		ApprovalID: "does-not-exist", ScopeID: scope.ID, Target: "example.com:443",
		Argv: json.RawMessage(`["nmap"]`),
	}); domain.AsToolError(err).Code != domain.CodeApprovalMismatch {
		t.Fatalf("unknown id code = %q", domain.AsToolError(err).Code)
	}

	// An approval that expires before use must not be consumable.
	expired, _, err := database.RequestApproval(ctx, domain.Approval{
		ID: "ap-expired-" + scope.ID, ScopeID: scope.ID, Target: "example.com:443",
		Argv: domain.NormalizeArgv([]string{"nmap", "example.com"}),
		Risk: domain.RiskActive, RequestedBy: "worker",
		ExpiresAt: time.Now().Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("RequestApproval() error = %v", err)
	}
	if _, err := database.DecideApproval(ctx, expired.ID, domain.ApprovalApproved, "analyst", ""); err == nil {
		t.Fatal("an already-expired approval must not be approvable")
	}
}
