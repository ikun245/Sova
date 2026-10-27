package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"soc/agent/internal/domain"
)

// OpenAIConfig is the transport-level configuration for one endpoint. It holds
// no vendor branching: anything speaking Chat Completions uses this adapter.
type OpenAIConfig struct {
	BaseURL        string
	APIKey         string
	Model          string
	Timeout        time.Duration
	MaxRetries     int
	MaxTokensField string
}

type OpenAI struct {
	baseURL        string
	apiKey         string
	model          string
	maxTokensField string
	maxRetries     int
	client         *http.Client
}

func NewOpenAI(config OpenAIConfig) (*OpenAI, error) {
	baseURL := strings.TrimSpace(config.BaseURL)
	if baseURL == "" {
		return nil, errors.New("llm: base_url is required")
	}
	// Tolerate a full endpoint URL so operators can paste either form.
	baseURL = strings.TrimRight(baseURL, "/")
	baseURL = strings.TrimSuffix(baseURL, "/chat/completions")
	baseURL = strings.TrimRight(baseURL, "/")
	if !strings.HasPrefix(baseURL, "http://") && !strings.HasPrefix(baseURL, "https://") {
		return nil, fmt.Errorf("llm: base_url %q must start with http:// or https://", baseURL)
	}
	if strings.TrimSpace(config.Model) == "" {
		return nil, errors.New("llm: model is required")
	}

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	maxTokensField := strings.TrimSpace(config.MaxTokensField)
	if maxTokensField == "" {
		maxTokensField = "max_tokens"
	}

	return &OpenAI{
		baseURL:        baseURL,
		apiKey:         config.APIKey,
		model:          config.Model,
		maxTokensField: maxTokensField,
		maxRetries:     max(config.MaxRetries, 0),
		client:         &http.Client{Timeout: timeout},
	}, nil
}

func (c *OpenAI) Model() string {
	return c.model
}

func (c *OpenAI) Complete(ctx context.Context, req domain.CompletionRequest) (domain.CompletionResponse, error) {
	model := req.Model
	if model == "" {
		model = c.model
	}
	payload, err := c.buildPayload(model, req)
	if err != nil {
		return domain.CompletionResponse{}, err
	}

	var lastErr error
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			if err := sleepCtx(ctx, backoff(attempt)); err != nil {
				return domain.CompletionResponse{}, err
			}
		}
		response, err := c.send(ctx, payload)
		if err == nil {
			return response, nil
		}
		lastErr = err
		if ctxErr := ctx.Err(); ctxErr != nil {
			return domain.CompletionResponse{}, ctxErr
		}
		if !retryable(err) {
			return domain.CompletionResponse{}, err
		}
	}
	return domain.CompletionResponse{}, fmt.Errorf("llm: giving up after %d attempts: %w", c.maxRetries+1, lastErr)
}

func (c *OpenAI) buildPayload(model string, req domain.CompletionRequest) ([]byte, error) {
	messages := make([]apiMessage, 0, len(req.Messages))
	for _, message := range req.Messages {
		converted := apiMessage{
			Role:       message.Role,
			Content:    message.Content,
			ToolCallID: message.ToolCallID,
			Name:       message.Name,
		}
		for _, call := range message.ToolCalls {
			converted.ToolCalls = append(converted.ToolCalls, apiToolCall{
				ID:   call.ID,
				Type: "function",
				Function: apiFunctionCall{
					Name:      call.Name,
					Arguments: string(call.Arguments),
				},
			})
		}
		messages = append(messages, converted)
	}

	body := map[string]any{
		"model":    model,
		"messages": messages,
	}
	if req.Temperature > 0 {
		body["temperature"] = req.Temperature
	}
	if req.MaxTokens > 0 {
		body[c.maxTokensField] = req.MaxTokens
	}
	if strings.TrimSpace(req.ReasoningEffort) != "" {
		body["reasoning_effort"] = req.ReasoningEffort
	}
	if len(req.Tools) > 0 {
		tools := make([]apiTool, 0, len(req.Tools))
		for _, tool := range req.Tools {
			parameters := tool.Parameters
			if len(parameters) == 0 {
				parameters = json.RawMessage(`{"type":"object","properties":{}}`)
			}
			tools = append(tools, apiTool{
				Type: "function",
				Function: apiFunction{
					Name:        tool.Name,
					Description: tool.Description,
					Parameters:  parameters,
				},
			})
		}
		body["tools"] = tools
	}
	if len(req.JSONSchema) > 0 {
		body["response_format"] = map[string]any{
			"type": "json_schema",
			"json_schema": map[string]any{
				"name":   "response",
				"schema": json.RawMessage(req.JSONSchema),
			},
		}
	}

	encoded, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("llm: encode request: %w", err)
	}
	return encoded, nil
}

func (c *OpenAI) send(ctx context.Context, payload []byte) (domain.CompletionResponse, error) {
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(payload))
	if err != nil {
		return domain.CompletionResponse{}, fmt.Errorf("llm: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	if c.apiKey != "" {
		httpReq.Header.Set("Authorization", "Bearer "+c.apiKey)
	}

	resp, err := c.client.Do(httpReq)
	if err != nil {
		return domain.CompletionResponse{}, fmt.Errorf("llm: request failed: %w", err)
	}
	defer resp.Body.Close()

	// Cap the error body: a broken gateway can return megabytes of HTML.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return domain.CompletionResponse{}, fmt.Errorf("llm: read response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return domain.CompletionResponse{}, &httpError{status: resp.StatusCode, body: truncate(string(raw), 512)}
	}

	var parsed chatResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return domain.CompletionResponse{}, fmt.Errorf("llm: decode response: %w", err)
	}
	if parsed.Error != nil && parsed.Error.Message != "" {
		return domain.CompletionResponse{}, fmt.Errorf("llm: provider error: %s", truncate(parsed.Error.Message, 512))
	}
	if len(parsed.Choices) == 0 {
		return domain.CompletionResponse{}, errors.New("llm: response contained no choices")
	}

	choice := parsed.Choices[0]
	result := domain.CompletionResponse{
		Content:      choice.Message.Content,
		FinishReason: choice.FinishReason,
		Usage: domain.Usage{
			InputTokens:  parsed.Usage.PromptTokens,
			OutputTokens: parsed.Usage.CompletionTokens,
		},
	}
	for _, call := range choice.Message.ToolCalls {
		arguments := strings.TrimSpace(call.Function.Arguments)
		if arguments == "" {
			arguments = "{}"
		}
		result.ToolCalls = append(result.ToolCalls, domain.ToolCall{
			ID:        call.ID,
			Name:      call.Function.Name,
			Arguments: json.RawMessage(arguments),
		})
	}
	return result, nil
}

type httpError struct {
	status int
	body   string
}

func (e *httpError) Error() string {
	return fmt.Sprintf("llm: endpoint returned HTTP %d: %s", e.status, e.body)
}

// retryable covers rate limits and transient server failures. Auth and
// validation errors are not retried because replaying them only wastes quota.
func retryable(err error) bool {
	var httpErr *httpError
	if errors.As(err, &httpErr) {
		return httpErr.status == http.StatusTooManyRequests || httpErr.status >= 500
	}
	return true
}

func backoff(attempt int) time.Duration {
	delay := 500 * time.Millisecond << (attempt - 1)
	if delay > 8*time.Second {
		delay = 8 * time.Second
	}
	return delay
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func truncate(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[:limit] + "..."
}

type apiMessage struct {
	Role       string        `json:"role"`
	Content    string        `json:"content,omitempty"`
	ToolCalls  []apiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
	Name       string        `json:"name,omitempty"`
}

type apiTool struct {
	Type     string      `json:"type"`
	Function apiFunction `json:"function"`
}

type apiFunction struct {
	Name        string          `json:"name"`
	Description string          `json:"description,omitempty"`
	Parameters  json.RawMessage `json:"parameters"`
}

type apiToolCall struct {
	ID       string          `json:"id"`
	Type     string          `json:"type"`
	Function apiFunctionCall `json:"function"`
}

type apiFunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				ID       string `json:"id"`
				Type     string `json:"type"`
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
	Error *struct {
		Message string `json:"message"`
		Type    string `json:"type"`
		Code    any    `json:"code"`
	} `json:"error"`
}
