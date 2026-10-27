package domain

import (
	"context"
	"encoding/json"
)

// Role names a business use of a model, not a vendor. Configuration binds a
// role to a model profile, so swapping providers never touches agent code.
type Role string

const (
	RoleTriage    Role = "triage"
	RoleSummary   Role = "summary"
	RoleEmbedding Role = "embedding"
	RoleRerank    Role = "rerank"
)

// Message is one turn in a model conversation. ToolCalls is set on assistant
// turns that requested tools; ToolCallID is set on tool result turns.
type Message struct {
	Role       string     `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
	Name       string     `json:"name,omitempty"`
}

// ToolDef is the model-facing schema of a callable tool. Parameters must be a
// JSON Schema object.
type ToolDef struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

// ToolCall is a model's request to invoke a tool. Arguments stay raw so the
// calling layer can validate them against the tool's schema before execution.
type ToolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type Usage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
}

type CompletionRequest struct {
	Model       string
	Messages    []Message
	Tools       []ToolDef
	Temperature float64
	MaxTokens   int
	// JSONSchema, when set, asks the provider for structured output. The
	// adapter decides how to express this; unsupported providers must fail
	// loudly rather than silently returning prose.
	JSONSchema json.RawMessage
	// ReasoningEffort is optional and adapter-specific; empty means "do not
	// send".
	ReasoningEffort string
}

type CompletionResponse struct {
	Content      string
	ToolCalls    []ToolCall
	Usage        Usage
	FinishReason string
}

// LLM is the only model dependency business code may use. Provider SDKs,
// HTTP details, and vendor JSON stay inside adapters.
type LLM interface {
	Complete(ctx context.Context, req CompletionRequest) (CompletionResponse, error)
	// Model reports the configured model id for cost attribution and logs.
	Model() string
}

type Embedder interface {
	Model() string
	Dim() int
	Embed(ctx context.Context, texts []string) ([][]float32, error)
}

type Ranked struct {
	Index int
	Score float64
}

type Reranker interface {
	Model() string
	Rerank(ctx context.Context, query string, docs []string, topK int) ([]Ranked, error)
}
