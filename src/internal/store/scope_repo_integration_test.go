//go:build integration

package store

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"soc/agent/internal/domain"
)

func newTestScope(t *testing.T, database *Postgres, workspaceID string) domain.TargetScope {
	t.Helper()
	ctx := context.Background()
	id := "scope-" + time.Now().Format("150405.000000000")
	scope := domain.TargetScope{
		ID:         id,
		TenantID:   domain.LocalTenantID,
		Domains:    []string{"example.com"},
		CIDRs:      []string{"203.0.113.0/24"},
		Ports:      []int{443},
		MaxRisk:    domain.RiskActive,
		ApprovedBy: "ciso",
		TicketID:   "SEC-" + id,
		ExpiresAt:  time.Now().Add(2 * time.Hour),
	}
	if _, err := database.CreateScope(ctx, workspaceID, scope); err != nil {
		t.Fatalf("CreateScope() error = %v", err)
	}
	t.Cleanup(func() {
		_, _ = database.db.ExecContext(context.Background(), `DELETE FROM scopes WHERE id = $1`, id)
	})
	return scope
}

func TestCreateScopeRoundTripsArraysAndRisk(t *testing.T) {
	database := openTestStore(t)
	workspaceID := newWorkspace(t, database)
	scope := newTestScope(t, database, workspaceID)

	record, err := database.GetScope(context.Background(), scope.ID)
	if err != nil {
		t.Fatalf("GetScope() error = %v", err)
	}
	if len(record.Scope.Domains) != 1 || record.Scope.Domains[0] != "example.com" {
		t.Fatalf("Domains = %v", record.Scope.Domains)
	}
	if len(record.Scope.CIDRs) != 1 || record.Scope.CIDRs[0] != "203.0.113.0/24" {
		t.Fatalf("CIDRs = %v", record.Scope.CIDRs)
	}
	if len(record.Scope.Ports) != 1 || record.Scope.Ports[0] != 443 {
		t.Fatalf("Ports = %v", record.Scope.Ports)
	}
	if record.Scope.MaxRisk != domain.RiskActive {
		t.Fatalf("MaxRisk = %q", record.Scope.MaxRisk)
	}
	if !record.Active(time.Now()) {
		t.Fatal("a fresh scope must be active")
	}
}

func TestCreateScopeRefusesBlanketAuthorization(t *testing.T) {
	database := openTestStore(t)
	workspaceID := newWorkspace(t, database)

	_, err := database.CreateScope(context.Background(), workspaceID, domain.TargetScope{
		ID: "bad", TenantID: domain.LocalTenantID, Domains: []string{"*"},
		MaxRisk: domain.RiskLight, ApprovedBy: "ciso", TicketID: "T1",
		ExpiresAt: time.Now().Add(time.Hour),
	})
	if err == nil {
		t.Fatal("the repository must reject a scope that authorizes everything")
	}
}

func TestPendingApprovalIsUniquePerScopeTargetArgv(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	workspaceID := newWorkspace(t, database)
	scope := newTestScope(t, database, workspaceID)

	argv := json.RawMessage(`["nmap","-sV","example.com"]`)
	first, created, err := database.RequestApproval(ctx, domain.Approval{
		ID: "ap1-" + scope.ID, ScopeID: scope.ID, Target: "example.com:443",
		Argv: argv, Risk: domain.RiskActive, RequestedBy: "worker",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("RequestApproval() error = %v", err)
	}
	if !created {
		t.Fatal("the first request should be created")
	}

	second, created, err := database.RequestApproval(ctx, domain.Approval{
		ID: "ap2-" + scope.ID, ScopeID: scope.ID, Target: "example.com:443",
		Argv: argv, Risk: domain.RiskActive, RequestedBy: "worker",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("second RequestApproval() error = %v", err)
	}
	if created {
		t.Fatal("an identical pending request must not be duplicated")
	}
	if second.ID != first.ID {
		t.Fatalf("returned %q, want the existing %q", second.ID, first.ID)
	}
}

func TestDecideApprovalIsSingleShot(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	workspaceID := newWorkspace(t, database)
	scope := newTestScope(t, database, workspaceID)

	approval, _, err := database.RequestApproval(ctx, domain.Approval{
		ID: "ap3-" + scope.ID, ScopeID: scope.ID, Target: "example.com:443",
		Argv: json.RawMessage(`["nmap"]`), Risk: domain.RiskActive, RequestedBy: "worker",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("RequestApproval() error = %v", err)
	}

	decided, err := database.DecideApproval(ctx, approval.ID, domain.ApprovalApproved, "analyst", "verified ticket")
	if err != nil {
		t.Fatalf("DecideApproval() error = %v", err)
	}
	if decided.Decision != domain.ApprovalApproved || decided.DecidedBy != "analyst" {
		t.Fatalf("approval = %+v", decided)
	}
	if !decided.Usable(time.Now()) {
		t.Fatal("an approved, unexpired approval must be usable")
	}

	// Deciding twice must not silently flip the decision.
	if _, err := database.DecideApproval(ctx, approval.ID, domain.ApprovalRejected, "someone", ""); err == nil {
		t.Fatal("a second decision must be refused")
	}
}

func TestRevokeScopeExpiresPendingApprovals(t *testing.T) {
	database := openTestStore(t)
	ctx := context.Background()
	workspaceID := newWorkspace(t, database)
	scope := newTestScope(t, database, workspaceID)

	approval, _, err := database.RequestApproval(ctx, domain.Approval{
		ID: "ap4-" + scope.ID, ScopeID: scope.ID, Target: "example.com:443",
		Argv: json.RawMessage(`["nmap"]`), Risk: domain.RiskActive, RequestedBy: "worker",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	})
	if err != nil {
		t.Fatalf("RequestApproval() error = %v", err)
	}

	if err := database.RevokeScope(ctx, scope.ID, "ciso"); err != nil {
		t.Fatalf("RevokeScope() error = %v", err)
	}

	stored, err := database.GetApproval(ctx, approval.ID)
	if err != nil {
		t.Fatalf("GetApproval() error = %v", err)
	}
	if stored.Decision != domain.ApprovalExpired {
		t.Fatalf("approval decision = %q, want expired after revocation", stored.Decision)
	}
	if stored.Usable(time.Now()) {
		t.Fatal("a pending approval must not survive scope revocation")
	}

	record, err := database.GetScope(ctx, scope.ID)
	if err != nil {
		t.Fatalf("GetScope() error = %v", err)
	}
	if record.Active(time.Now()) {
		t.Fatal("a revoked scope must not report active")
	}
}
