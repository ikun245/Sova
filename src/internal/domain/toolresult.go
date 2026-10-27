package domain

import (
	"encoding/json"
	"errors"
	"fmt"
)

// ErrorCode is a stable, machine-readable classification of a tool outcome.
// Models branch on these codes; free-form messages are for humans only and must
// never be the sole carrier of meaning.
type ErrorCode string

const (
	// CodeInvalidArgument means the tool input was unusable. The model can fix
	// this by changing its arguments; no state changed.
	CodeInvalidArgument ErrorCode = "invalid_argument"
	// CodeToolNotFound means the requested tool does not exist. Retrying is
	// pointless.
	CodeToolNotFound ErrorCode = "tool_not_found"
	// CodePolicyDenied means a code-level rule refused the command, e.g. a
	// destructive pattern or an unclassified binary. Never retryable.
	CodePolicyDenied ErrorCode = "policy_denied"
	// CodeOutOfScope means the target is not authorized by the engagement.
	// Retrying the same target is pointless; a new scope needs a human.
	CodeOutOfScope ErrorCode = "out_of_scope"
	// CodeScopeExpired means the authorization window closed.
	CodeScopeExpired ErrorCode = "scope_expired"
	// CodeApprovalRequired means the action is allowed but needs a human
	// approval id. Retryable once an approval is granted.
	CodeApprovalRequired ErrorCode = "approval_required"
	// CodeApprovalRejected means a human denied the action. Never retryable.
	CodeApprovalRejected ErrorCode = "approval_rejected"
	// CodeApprovalMismatch means the supplied approval exists but does not
	// authorize this exact command against this exact target. Treated as a
	// denial: an approval is bound to one request, not to a tool in general.
	CodeApprovalMismatch ErrorCode = "approval_mismatch"
	// CodeApprovalConsumed means the approval was already spent. One approval
	// authorizes one call, so replaying it is indistinguishable from not having
	// it at all.
	CodeApprovalConsumed ErrorCode = "approval_consumed"
	// CodeBinaryMissing means the tool binary is not installed.
	CodeBinaryMissing ErrorCode = "binary_missing"
	// CodeTimeout means the command exceeded its budget.
	CodeTimeout ErrorCode = "timeout"
	// CodeCommandFailed means the process ran and exited non-zero.
	CodeCommandFailed ErrorCode = "command_failed"
	// CodeBudgetExceeded means an agent or task budget ran out.
	CodeBudgetExceeded ErrorCode = "budget_exceeded"
	// CodeInvalidOutput means a model response could not be parsed into the
	// required schema.
	CodeInvalidOutput ErrorCode = "invalid_output"
	// CodeInternal means the platform failed, not the model. Safe to retry.
	CodeInternal ErrorCode = "internal_error"
)

// retryableCodes are the only codes where retrying the same call can succeed
// without a human or a configuration change.
var retryableCodes = map[ErrorCode]bool{
	CodeApprovalRequired: true,
	CodeTimeout:          true,
	CodeInternal:         true,
}

// Retryable reports whether the same call may be attempted again.
func (c ErrorCode) Retryable() bool {
	return retryableCodes[c]
}

// ToolError is the single error shape every tool returns. It carries a stable
// code, a human message, and an actionable hint so a model can decide whether to
// retry, change arguments, or escalate — without guessing.
type ToolError struct {
	Code    ErrorCode `json:"code"`
	Message string    `json:"message"`
	// Hint tells the caller what to do next. It is written for a model, so it
	// states the action rather than describing the failure again.
	Hint string `json:"hint,omitempty"`
	// Details carries structured context such as target, ticket, or the risk
	// level required to proceed.
	Details map[string]string `json:"details,omitempty"`

	cause error
}

func (e *ToolError) Error() string {
	if e == nil {
		return ""
	}
	if e.Message != "" {
		return fmt.Sprintf("%s: %s", e.Code, e.Message)
	}
	return string(e.Code)
}

// Unwrap keeps errors.Is/errors.As working for Go callers.
func (e *ToolError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.cause
}

// Is lets errors.Is(err, ErrDenied) keep working now that failures carry codes.
// Go callers get ergonomics; the model gets a stable code.
func (e *ToolError) Is(target error) bool {
	if e == nil {
		return false
	}
	switch target {
	case ErrDenied:
		return e.Code == CodePolicyDenied || e.Code == CodeOutOfScope || e.Code == CodeScopeExpired
	case ErrNeedsApproval:
		return e.Code == CodeApprovalRequired
	}
	return false
}

// Retryable reports whether the caller may retry the same request.
func (e *ToolError) Retryable() bool {
	if e == nil {
		return false
	}
	return e.Code.Retryable()
}

// NewToolError builds a coded error. Details may be nil.
func NewToolError(code ErrorCode, message, hint string) *ToolError {
	return &ToolError{Code: code, Message: message, Hint: hint}
}

// WrapToolError attaches an underlying cause for logging while keeping the
// stable code the model sees.
func WrapToolError(code ErrorCode, message, hint string, cause error) *ToolError {
	return &ToolError{Code: code, Message: message, Hint: hint, cause: cause}
}

// WithDetail returns a copy with one structured detail added.
func (e *ToolError) WithDetail(key, value string) *ToolError {
	if e == nil {
		return nil
	}
	copied := *e
	copied.Details = make(map[string]string, len(e.Details)+1)
	for k, v := range e.Details {
		copied.Details[k] = v
	}
	if value != "" {
		copied.Details[key] = value
	}
	return &copied
}

// AsToolError extracts a coded error from any error chain. An uncoded error is
// reported as CodeInternal so callers never have to special-case nil codes.
func AsToolError(err error) *ToolError {
	if err == nil {
		return nil
	}
	var toolErr *ToolError
	if errors.As(err, &toolErr) {
		return toolErr
	}
	return &ToolError{Code: CodeInternal, Message: err.Error(), cause: err}
}

// ResultMeta describes how a tool call was performed. It is always present so a
// model can reason about cost, risk, and truncation.
type ResultMeta struct {
	Tool       string `json:"tool"`
	Risk       string `json:"risk,omitempty"`
	Target     string `json:"target,omitempty"`
	ExitCode   int    `json:"exit_code,omitempty"`
	DurationMS int64  `json:"duration_ms,omitempty"`
	Truncated  bool   `json:"truncated"`
	TimedOut   bool   `json:"timed_out"`
	AuditID    string `json:"audit_id,omitempty"`
}

// ToolResult is the single shape every tool returns to a model. Success and
// failure share it, so a model never has to interpret two different formats.
type ToolResult struct {
	OK        bool              `json:"ok"`
	Code      ErrorCode         `json:"code"`
	Message   string            `json:"message,omitempty"`
	Hint      string            `json:"hint,omitempty"`
	Retryable bool              `json:"retryable"`
	Details   map[string]string `json:"details,omitempty"`
	Data      any               `json:"data,omitempty"`
	Meta      *ResultMeta       `json:"meta,omitempty"`
}

// Success builds a successful result.
func Success(code ErrorCode, data any) ToolResult {
	if code == "" {
		code = "ok"
	}
	return ToolResult{OK: true, Code: code, Data: data}
}

// Failure builds a failed result from a coded error.
func Failure(err error) ToolResult {
	toolErr := AsToolError(err)
	if toolErr == nil {
		return ToolResult{OK: true, Code: "ok"}
	}
	return ToolResult{
		OK:        false,
		Code:      toolErr.Code,
		Message:   toolErr.Message,
		Hint:      toolErr.Hint,
		Retryable: toolErr.Retryable(),
		Details:   toolErr.Details,
	}
}

// WithMeta attaches execution metadata.
func (r ToolResult) WithMeta(meta *ResultMeta) ToolResult {
	r.Meta = meta
	return r
}

// JSON renders the result for a model. Marshalling cannot fail for this struct,
// but a failure still returns a valid envelope so the caller never sees prose.
func (r ToolResult) JSON() string {
	encoded, err := json.Marshal(r)
	if err != nil {
		fallback, _ := json.Marshal(ToolResult{
			OK:      false,
			Code:    CodeInternal,
			Message: "failed to encode tool result",
		})
		return string(fallback)
	}
	return string(encoded)
}

// ErrDenied and ErrNeedsApproval remain the Go-level sentinels so existing
// callers keep compiling. Coded errors report them through Is.
var (
	ErrDenied        = errors.New("denied")
	ErrNeedsApproval = errors.New("approval required")
)
