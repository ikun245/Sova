package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"soc/agent/internal/domain"
	"soc/agent/internal/store"
)

type fakeScopes struct {
	created   domain.TargetScope
	approval  domain.Approval
	records   []domain.ScopeRecord
	createErr error
	getErr    error
	decideErr error
	revoked   bool
	duplicate bool
}

func (f *fakeScopes) CreateScope(_ context.Context, _ string, scope domain.TargetScope) (domain.TargetScope, error) {
	if f.createErr != nil {
		return domain.TargetScope{}, f.createErr
	}
	f.created = scope
	return scope, nil
}

func (f *fakeScopes) GetScope(context.Context, string) (domain.ScopeRecord, error) {
	if f.getErr != nil {
		return domain.ScopeRecord{}, f.getErr
	}
	if len(f.records) > 0 {
		return f.records[0], nil
	}
	return domain.ScopeRecord{Scope: domain.TargetScope{ID: "s1", ExpiresAt: time.Now().Add(time.Hour)}}, nil
}

func (f *fakeScopes) ListScopes(context.Context, string, bool) ([]domain.ScopeRecord, error) {
	return f.records, nil
}

func (f *fakeScopes) RevokeScope(context.Context, string, string) error {
	f.revoked = true
	return nil
}

func (f *fakeScopes) RequestApproval(_ context.Context, approval domain.Approval) (domain.Approval, bool, error) {
	f.approval = approval
	return approval, !f.duplicate, nil
}

func (f *fakeScopes) DecideApproval(_ context.Context, _, decision, decidedBy, _ string) (domain.Approval, error) {
	if f.decideErr != nil {
		return domain.Approval{}, f.decideErr
	}
	return domain.Approval{ID: "a1", Decision: decision, DecidedBy: decidedBy}, nil
}

func (f *fakeScopes) GetApproval(context.Context, string) (domain.Approval, error) {
	return domain.Approval{}, store.ErrApprovalNotFound
}

func (f *fakeScopes) ListApprovals(context.Context, string, int) ([]domain.Approval, error) {
	return nil, nil
}

func scopeRouter(scopes domain.ScopeRepository) http.Handler {
	return NewRouter(nil, func(context.Context) error { return nil }, RouterDeps{Scopes: scopes})
}

func decodeBody(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var body map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &body); err != nil {
		t.Fatalf("response is not JSON: %v (body: %s)", err, recorder.Body.String())
	}
	return body
}

func TestCreateScopeStoresApprovedEngagement(t *testing.T) {
	scopes := &fakeScopes{}
	router := scopeRouter(scopes)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/scopes", strings.NewReader(`{
		"workspace_id":"ws-1","domains":["example.com"],"ports":[80,443],
		"max_risk":"active","approved_by":"ciso","ticket_id":"SEC-1","expires_in_hours":24
	}`))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusCreated {
		t.Fatalf("status = %d, want 201; body: %s", recorder.Code, recorder.Body.String())
	}
	if scopes.created.ApprovedBy != "ciso" || scopes.created.TicketID != "SEC-1" {
		t.Fatalf("approval metadata lost: %+v", scopes.created)
	}
	if scopes.created.MaxRisk != domain.RiskActive {
		t.Fatalf("MaxRisk = %q", scopes.created.MaxRisk)
	}
}

func TestCreateScopeRejectsUnboundedWindow(t *testing.T) {
	router := scopeRouter(&fakeScopes{})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/scopes", strings.NewReader(`{
		"workspace_id":"ws-1","domains":["example.com"],"max_risk":"light",
		"approved_by":"ciso","ticket_id":"SEC-1","expires_in_hours":100000
	}`))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	body := decodeBody(t, recorder)
	if body["code"] != string(domain.CodeInvalidArgument) {
		t.Fatalf("code = %v, want %q", body["code"], domain.CodeInvalidArgument)
	}
	if body["hint"] == nil {
		t.Fatal("the error must tell the client how to fix it")
	}
}

func TestCreateScopeRejectsBlanketAuthorization(t *testing.T) {
	scopes := &fakeScopes{createErr: errors.New(`scope "x" must not authorize every domain`)}
	router := scopeRouter(scopes)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/scopes", strings.NewReader(`{
		"workspace_id":"ws-1","domains":["*"],"max_risk":"light",
		"approved_by":"ciso","ticket_id":"SEC-1","expires_in_hours":1
	}`))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if decodeBody(t, recorder)["code"] != string(domain.CodeInvalidArgument) {
		t.Fatal("a blanket scope must be reported as invalid input")
	}
}

func TestRequestApprovalReturnsAcceptedAndHint(t *testing.T) {
	scopes := &fakeScopes{}
	router := scopeRouter(scopes)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/approvals", strings.NewReader(`{
		"scope_id":"s1","target":"example.com:443","argv":["nmap","-sV","example.com"],
		"risk":"active","requested_by":"worker"
	}`))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body: %s", recorder.Code, recorder.Body.String())
	}
	body := decodeBody(t, recorder)
	if body["code"] != "approval_pending" {
		t.Fatalf("code = %v", body["code"])
	}
	if body["hint"] == nil {
		t.Fatal("the agent needs a hint to know it must wait for a human")
	}
}

func TestRequestApprovalRejectsRevokedScope(t *testing.T) {
	revoked := time.Now()
	scopes := &fakeScopes{records: []domain.ScopeRecord{{
		Scope:     domain.TargetScope{ID: "s1", ExpiresAt: time.Now().Add(time.Hour)},
		RevokedAt: &revoked,
	}}}
	router := scopeRouter(scopes)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/approvals", strings.NewReader(`{
		"scope_id":"s1","target":"example.com","argv":["nmap"],"risk":"active","requested_by":"worker"
	}`))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403", recorder.Code)
	}
	if decodeBody(t, recorder)["code"] != string(domain.CodeScopeExpired) {
		t.Fatal("a revoked scope must be reported as expired, not as a generic denial")
	}
}

func TestDecideApprovalRequiresPerson(t *testing.T) {
	router := scopeRouter(&fakeScopes{})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/a1/decide",
		strings.NewReader(`{"decision":"approved"}`))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", recorder.Code)
	}
	if decodeBody(t, recorder)["code"] != string(domain.CodeInvalidArgument) {
		t.Fatal("an approval without a person must be refused")
	}
}

func TestDecideApprovalConflictReportsInvalidTransition(t *testing.T) {
	scopes := &fakeScopes{decideErr: store.ErrInvalidTransition}
	router := scopeRouter(scopes)

	request := httptest.NewRequest(http.MethodPost, "/api/v1/approvals/a1/decide",
		strings.NewReader(`{"decision":"approved","decided_by":"analyst"}`))
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", recorder.Code)
	}
	body := decodeBody(t, recorder)
	if body["retryable"] != false {
		t.Fatal("a stale approval must not be marked retryable")
	}
}

func TestScopeRoutesAbsentWithoutRepository(t *testing.T) {
	router := NewRouter(nil, func(context.Context) error { return nil })
	request := httptest.NewRequest(http.MethodGet, "/api/v1/scopes?workspace_id=ws-1", nil)
	recorder := httptest.NewRecorder()
	router.ServeHTTP(recorder, request)

	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404 when scopes are not wired", recorder.Code)
	}
}
