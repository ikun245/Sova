package api

import (
	"encoding/json"
	"net/http"

	"soc/agent/internal/domain"
)

// errorBody is the HTTP counterpart of domain.ToolResult. Both use the same
// stable codes so a human client and an agent interpret a failure identically.
type errorBody struct {
	OK        bool              `json:"ok"`
	Code      string            `json:"code"`
	Message   string            `json:"message"`
	Hint      string            `json:"hint,omitempty"`
	Retryable bool              `json:"retryable"`
	Details   map[string]string `json:"details,omitempty"`
	RequestID string            `json:"request_id"`
}

func writeError(w http.ResponseWriter, r *http.Request, status int, code, message string) {
	writeCodedError(w, r, status, domain.ToolResult{
		OK:        false,
		Code:      domain.ErrorCode(code),
		Message:   message,
		Retryable: status == http.StatusTooManyRequests || status >= 500,
	})
}

// writeCodedError renders a coded failure with the shape a model already knows
// from tool calls, so the same client code can handle both transports.
func writeCodedError(w http.ResponseWriter, r *http.Request, status int, result domain.ToolResult) {
	body := errorBody{
		OK:        false,
		Code:      string(result.Code),
		Message:   result.Message,
		Hint:      result.Hint,
		Retryable: result.Retryable,
		Details:   result.Details,
		RequestID: w.Header().Get("X-Request-ID"),
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

// statusForCode maps a stable code to the HTTP status that carries the same
// meaning. Keeping this table explicit stops the two vocabularies from drifting.
func statusForCode(code domain.ErrorCode) int {
	switch code {
	case domain.CodeInvalidArgument, domain.CodeInvalidOutput:
		return http.StatusBadRequest
	case domain.CodeToolNotFound:
		return http.StatusNotFound
	case domain.CodePolicyDenied, domain.CodeOutOfScope, domain.CodeScopeExpired, domain.CodeApprovalRejected:
		return http.StatusForbidden
	case domain.CodeApprovalRequired:
		return http.StatusConflict
	case domain.CodeBudgetExceeded, domain.CodeTimeout:
		return http.StatusTooManyRequests
	default:
		return http.StatusInternalServerError
	}
}

// writeToolResult renders a tool result over HTTP using the same body shape.
func writeToolResult(w http.ResponseWriter, r *http.Request, result domain.ToolResult) {
	status := http.StatusOK
	if !result.OK {
		status = statusForCode(result.Code)
	}
	body := errorBody{
		OK:        result.OK,
		Code:      string(result.Code),
		Message:   result.Message,
		Hint:      result.Hint,
		Retryable: result.Retryable,
		Details:   result.Details,
		RequestID: w.Header().Get("X-Request-ID"),
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}
