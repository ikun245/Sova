package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"soc/agent/internal/domain"
	"soc/agent/internal/store"
)

// scopeHandlers expose engagement scopes and per-command approvals.
//
// The write paths are deliberately explicit about who approved what: a scope
// without approved_by/ticket_id is refused by the repository, so these handlers
// cannot be used to create an anonymous authorization.
type scopeHandlers struct {
	scopes domain.ScopeRepository
}

type createScopeRequest struct {
	WorkspaceID      string           `json:"workspace_id"`
	Domains          []string         `json:"domains"`
	CIDRs            []string         `json:"cidrs"`
	Ports            []int            `json:"ports"`
	MaxRisk          domain.RiskLevel `json:"max_risk"`
	MaxRatePerMinute int              `json:"max_rate_per_minute"`
	ApprovedBy       string           `json:"approved_by"`
	TicketID         string           `json:"ticket_id"`
	// ExpiresInHours is used instead of an absolute timestamp so a client
	// cannot submit an already-expired or absurdly long window by accident.
	ExpiresInHours int `json:"expires_in_hours"`
}

func (h scopeHandlers) create(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req createScopeRequest
	if err := decoder.Decode(&req); err != nil {
		writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
			OK: false, Code: domain.CodeInvalidArgument,
			Message: "request body must be valid JSON with the documented fields",
			Hint:    "see POST /api/v1/scopes for the expected shape",
		})
		return
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
			OK: false, Code: domain.CodeInvalidArgument, Message: "request body must contain exactly one JSON value",
		})
		return
	}

	if strings.TrimSpace(req.WorkspaceID) == "" {
		writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
			OK: false, Code: domain.CodeInvalidArgument, Message: "workspace_id is required",
			Hint: "create the scope inside a workspace so its team can be resolved",
		})
		return
	}
	if req.ExpiresInHours <= 0 {
		writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
			OK: false, Code: domain.CodeInvalidArgument, Message: "expires_in_hours must be positive",
			Hint: "authorizations always expire; pick a bounded window",
		})
		return
	}
	// Cap the window: a multi-year authorization is almost always a mistake.
	if req.ExpiresInHours > 24*90 {
		writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
			OK: false, Code: domain.CodeInvalidArgument, Message: "expires_in_hours must not exceed 2160 (90 days)",
			Hint: "shorten the window and renew it explicitly",
		})
		return
	}

	id, err := newScopeID()
	if err != nil {
		writeCodedError(w, r, http.StatusInternalServerError, domain.ToolResult{
			OK: false, Code: domain.CodeInternal, Message: "could not generate a scope id",
		})
		return
	}

	scope := domain.TargetScope{
		ID:               id,
		TenantID:         domain.LocalTenantID,
		Domains:          req.Domains,
		CIDRs:            req.CIDRs,
		Ports:            req.Ports,
		MaxRisk:          req.MaxRisk,
		MaxRatePerMinute: req.MaxRatePerMinute,
		ExpiresAt:        time.Now().Add(time.Duration(req.ExpiresInHours) * time.Hour),
		ApprovedBy:       strings.TrimSpace(req.ApprovedBy),
		TicketID:         strings.TrimSpace(req.TicketID),
	}

	stored, err := h.scopes.CreateScope(r.Context(), req.WorkspaceID, scope)
	if err != nil {
		h.writeScopeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":           true,
		"code":         "created",
		"workspace_id": req.WorkspaceID,
		"scope":        stored,
	})
}

func (h scopeHandlers) list(w http.ResponseWriter, r *http.Request) {
	workspaceID := strings.TrimSpace(r.URL.Query().Get("workspace_id"))
	if workspaceID == "" {
		writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
			OK: false, Code: domain.CodeInvalidArgument, Message: "workspace_id query parameter is required",
		})
		return
	}
	includeRevoked := r.URL.Query().Get("include_revoked") == "true"

	records, err := h.scopes.ListScopes(r.Context(), workspaceID, includeRevoked)
	if err != nil {
		h.writeScopeError(w, r, err)
		return
	}

	now := time.Now()
	type scopeView struct {
		domain.TargetScope
		WorkspaceID string `json:"workspace_id"`
		Active      bool   `json:"active"`
	}
	views := make([]scopeView, 0, len(records))
	for _, record := range records {
		views = append(views, scopeView{
			TargetScope: record.Scope,
			WorkspaceID: record.WorkspaceID,
			Active:      record.Active(now),
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"code":  "ok",
		"items": views,
		"total": len(views),
	})
}

func (h scopeHandlers) revoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
			OK: false, Code: domain.CodeInvalidArgument, Message: "scope id is required in the path",
		})
		return
	}
	revokedBy := strings.TrimSpace(r.URL.Query().Get("by"))
	if revokedBy == "" {
		writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
			OK: false, Code: domain.CodeInvalidArgument, Message: "the by query parameter is required",
			Hint: "record who revoked the authorization",
		})
		return
	}

	if err := h.scopes.RevokeScope(r.Context(), id, revokedBy); err != nil {
		h.writeScopeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":      true,
		"code":    "revoked",
		"scope":   id,
		"by":      revokedBy,
		"pending": "pending approvals for this scope were expired",
	})
}

type requestApprovalRequest struct {
	ScopeID     string           `json:"scope_id"`
	Target      string           `json:"target"`
	Argv        json.RawMessage  `json:"argv"`
	Risk        domain.RiskLevel `json:"risk"`
	RequestedBy string           `json:"requested_by"`
	TTLMinutes  int              `json:"ttl_minutes"`
}

func (h scopeHandlers) requestApproval(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req requestApprovalRequest
	if err := decoder.Decode(&req); err != nil {
		writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
			OK: false, Code: domain.CodeInvalidArgument, Message: "request body must be valid JSON",
		})
		return
	}
	if req.ScopeID == "" || req.Target == "" || req.RequestedBy == "" || len(req.Argv) == 0 {
		writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
			OK: false, Code: domain.CodeInvalidArgument,
			Message: "scope_id, target, argv and requested_by are required",
		})
		return
	}

	// The scope must exist and be active: an approval against a revoked scope
	// would authorize nothing.
	record, err := h.scopes.GetScope(r.Context(), req.ScopeID)
	if err != nil {
		h.writeScopeError(w, r, err)
		return
	}
	if !record.Active(time.Now()) {
		writeCodedError(w, r, http.StatusForbidden, domain.ToolResult{
			OK: false, Code: domain.CodeScopeExpired,
			Message: "the referenced scope is revoked or expired",
			Hint:    "create a new scope before requesting approval",
		})
		return
	}

	ttl := req.TTLMinutes
	if ttl <= 0 {
		ttl = 15
	}
	if ttl > 24*60 {
		writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
			OK: false, Code: domain.CodeInvalidArgument, Message: "ttl_minutes must not exceed 1440",
		})
		return
	}

	id, err := newScopeID()
	if err != nil {
		writeCodedError(w, r, http.StatusInternalServerError, domain.ToolResult{
			OK: false, Code: domain.CodeInternal, Message: "could not generate an approval id",
		})
		return
	}

	stored, created, err := h.scopes.RequestApproval(r.Context(), domain.Approval{
		ID:          id,
		ScopeID:     req.ScopeID,
		Target:      req.Target,
		Argv:        req.Argv,
		Risk:        req.Risk,
		RequestedBy: req.RequestedBy,
		ExpiresAt:   time.Now().Add(time.Duration(ttl) * time.Minute),
	})
	if err != nil {
		h.writeScopeError(w, r, err)
		return
	}

	status := http.StatusAccepted
	code := "approval_pending"
	hint := "a human must decide; retry the command with approval_id once approved"
	if !created {
		code = "approval_already_pending"
		hint = "an identical request is already waiting; reuse its id"
	}
	writeJSON(w, status, map[string]any{
		"ok":       true,
		"code":     code,
		"approval": stored,
		"hint":     hint,
	})
}

type decideApprovalRequest struct {
	Decision  string `json:"decision"`
	DecidedBy string `json:"decided_by"`
	Reason    string `json:"reason"`
}

func (h scopeHandlers) decideApproval(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	var req decideApprovalRequest
	if err := decoder.Decode(&req); err != nil {
		writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
			OK: false, Code: domain.CodeInvalidArgument, Message: "request body must be valid JSON",
		})
		return
	}
	if req.Decision != domain.ApprovalApproved && req.Decision != domain.ApprovalRejected {
		writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
			OK: false, Code: domain.CodeInvalidArgument, Message: "decision must be approved or rejected",
		})
		return
	}
	if strings.TrimSpace(req.DecidedBy) == "" {
		writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
			OK: false, Code: domain.CodeInvalidArgument, Message: "decided_by is required",
			Hint: "an approval without a person is not an approval",
		})
		return
	}

	approval, err := h.scopes.DecideApproval(r.Context(), id, req.Decision, strings.TrimSpace(req.DecidedBy), req.Reason)
	if err != nil {
		h.writeScopeError(w, r, err)
		return
	}

	code := "approved"
	if approval.Decision == domain.ApprovalRejected {
		code = "rejected"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":       true,
		"code":     code,
		"approval": approval,
	})
}

func (h scopeHandlers) listApprovals(w http.ResponseWriter, r *http.Request) {
	decision := strings.TrimSpace(r.URL.Query().Get("decision"))
	switch decision {
	case "", domain.ApprovalPending, domain.ApprovalApproved, domain.ApprovalRejected, domain.ApprovalExpired:
	default:
		writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
			OK: false, Code: domain.CodeInvalidArgument,
			Message: "decision must be one of pending, approved, rejected, expired",
		})
		return
	}

	approvals, err := h.scopes.ListApprovals(r.Context(), decision, 100)
	if err != nil {
		h.writeScopeError(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":    true,
		"code":  "ok",
		"items": approvals,
		"total": len(approvals),
	})
}

// writeScopeError maps repository errors to the shared code vocabulary so HTTP
// clients and agents see the same semantics.
func (h scopeHandlers) writeScopeError(w http.ResponseWriter, r *http.Request, err error) {
	var toolErr *domain.ToolError
	if errors.As(err, &toolErr) {
		writeCodedError(w, r, statusForCode(toolErr.Code), domain.Failure(err))
		return
	}

	switch {
	case errors.Is(err, store.ErrScopeNotFound), errors.Is(err, store.ErrApprovalNotFound):
		writeCodedError(w, r, http.StatusNotFound, domain.ToolResult{
			OK: false, Code: domain.CodeToolNotFound, Message: err.Error(),
		})
	case errors.Is(err, store.ErrScopeExpired), errors.Is(err, domain.ErrDenied):
		writeCodedError(w, r, http.StatusForbidden, domain.ToolResult{
			OK: false, Code: domain.CodeScopeExpired, Message: err.Error(),
			Hint: "create a new authorization window",
		})
	case errors.Is(err, store.ErrInvalidTransition):
		writeCodedError(w, r, http.StatusConflict, domain.ToolResult{
			OK: false, Code: domain.CodeApprovalRejected, Message: err.Error(),
			Hint: "this approval is no longer pending; request a new one",
		})
	case errors.Is(err, domain.ErrNeedsApproval):
		writeCodedError(w, r, http.StatusConflict, domain.ToolResult{
			OK: false, Code: domain.CodeApprovalRequired, Message: err.Error(),
		})
	default:
		slog.ErrorContext(r.Context(), "scope request failed", "error", err, "request_id", w.Header().Get("X-Request-ID"))
		// Validation errors from TargetScope.Validate arrive as plain errors;
		// they are the caller's fault, not ours.
		if isValidationError(err) {
			writeCodedError(w, r, http.StatusBadRequest, domain.ToolResult{
				OK: false, Code: domain.CodeInvalidArgument, Message: err.Error(),
				Hint: "fix the scope definition: an empty, blanket, or unbounded scope is rejected",
			})
			return
		}
		writeCodedError(w, r, http.StatusInternalServerError, domain.ToolResult{
			OK: false, Code: domain.CodeInternal, Message: "the scope operation failed",
		})
	}
}

// isValidationError recognises the plain errors produced by scope validation.
func isValidationError(err error) bool {
	message := err.Error()
	for _, marker := range []string{
		"authorizes no targets", "unknown max risk", "invalid CIDR",
		"must not authorize", "has no max risk level", "requires approved_by",
	} {
		if strings.Contains(message, marker) {
			return true
		}
	}
	return false
}

func newScopeID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
