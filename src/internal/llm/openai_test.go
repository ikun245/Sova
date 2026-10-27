package llm

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"soc/agent/internal/domain"
)

func newTestClient(t *testing.T, handler http.HandlerFunc) *OpenAI {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	client, err := NewOpenAI(OpenAIConfig{
		BaseURL:    server.URL,
		APIKey:     "test-key",
		Model:      "test-model",
		Timeout:    5 * time.Second,
		MaxRetries: 0,
	})
	if err != nil {
		t.Fatalf("NewOpenAI() error = %v", err)
	}
	return client
}

func TestCompleteParsesContentAndUsage(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer test-key" {
			t.Errorf("Authorization = %q", got)
		}
		_, _ = w.Write([]byte(`{
			"choices":[{"message":{"content":"hello"},"finish_reason":"stop"}],
			"usage":{"prompt_tokens":11,"completion_tokens":7}
		}`))
	})

	response, err := client.Complete(context.Background(), domain.CompletionRequest{
		Messages: []domain.Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if response.Content != "hello" {
		t.Fatalf("Content = %q, want hello", response.Content)
	}
	if response.Usage.InputTokens != 11 || response.Usage.OutputTokens != 7 {
		t.Fatalf("Usage = %+v, want 11/7", response.Usage)
	}
	if response.FinishReason != "stop" {
		t.Fatalf("FinishReason = %q, want stop", response.FinishReason)
	}
}

func TestCompleteParsesToolCalls(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{
			"choices":[{"message":{"tool_calls":[
				{"id":"call-1","type":"function","function":{"name":"lookup_asset","arguments":"{\"ip\":\"10.0.0.1\"}"}}
			]},"finish_reason":"tool_calls"}]
		}`))
	})

	response, err := client.Complete(context.Background(), domain.CompletionRequest{
		Messages: []domain.Message{{Role: "user", Content: "check"}},
	})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if len(response.ToolCalls) != 1 {
		t.Fatalf("ToolCalls = %d, want 1", len(response.ToolCalls))
	}
	call := response.ToolCalls[0]
	if call.ID != "call-1" || call.Name != "lookup_asset" {
		t.Fatalf("ToolCall = %+v", call)
	}
	var arguments map[string]string
	if err := json.Unmarshal(call.Arguments, &arguments); err != nil {
		t.Fatalf("decode arguments: %v", err)
	}
	if arguments["ip"] != "10.0.0.1" {
		t.Fatalf("arguments = %v", arguments)
	}
}

func TestCompleteSendsConfiguredProtocolFields(t *testing.T) {
	var captured map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/chat/completions" {
			t.Errorf("path = %q, want /chat/completions", r.URL.Path)
		}
		if err := json.NewDecoder(r.Body).Decode(&captured); err != nil {
			t.Errorf("decode request: %v", err)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"ok"}}]}`))
	}))
	t.Cleanup(server.Close)

	client, err := NewOpenAI(OpenAIConfig{
		BaseURL:        server.URL + "/chat/completions",
		Model:          "test-model",
		MaxTokensField: "max_completion_tokens",
	})
	if err != nil {
		t.Fatalf("NewOpenAI() error = %v", err)
	}

	_, err = client.Complete(context.Background(), domain.CompletionRequest{
		Messages:   []domain.Message{{Role: "user", Content: "hi"}},
		MaxTokens:  256,
		Tools:      []domain.ToolDef{{Name: "lookup", Description: "look up", Parameters: json.RawMessage(`{"type":"object"}`)}},
		JSONSchema: json.RawMessage(`{"type":"object","properties":{"verdict":{"type":"string"}}}`),
	})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}

	if captured["model"] != "test-model" {
		t.Fatalf("model = %v", captured["model"])
	}
	if _, ok := captured["max_completion_tokens"]; !ok {
		t.Fatal("expected the configured max tokens field name")
	}
	if _, ok := captured["max_tokens"]; ok {
		t.Fatal("must not send max_tokens when max_completion_tokens is configured")
	}
	if _, ok := captured["tools"]; !ok {
		t.Fatal("expected tools in request")
	}
	format, ok := captured["response_format"].(map[string]any)
	if !ok || format["type"] != "json_schema" {
		t.Fatalf("response_format = %v", captured["response_format"])
	}
}

func TestCompleteRetriesRateLimit(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		if atomic.AddInt32(&attempts, 1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			_, _ = w.Write([]byte(`{"error":{"message":"slow down"}}`))
			return
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"recovered"}}]}`))
	}))
	t.Cleanup(server.Close)

	client, err := NewOpenAI(OpenAIConfig{BaseURL: server.URL, Model: "m", MaxRetries: 1})
	if err != nil {
		t.Fatalf("NewOpenAI() error = %v", err)
	}

	response, err := client.Complete(context.Background(), domain.CompletionRequest{
		Messages: []domain.Message{{Role: "user", Content: "hi"}},
	})
	if err != nil {
		t.Fatalf("Complete() error = %v", err)
	}
	if response.Content != "recovered" {
		t.Fatalf("Content = %q", response.Content)
	}
	if atomic.LoadInt32(&attempts) != 2 {
		t.Fatalf("attempts = %d, want 2", attempts)
	}
}

func TestCompleteDoesNotRetryBadRequest(t *testing.T) {
	var attempts int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt32(&attempts, 1)
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(`{"error":{"message":"bad model"}}`))
	}))
	t.Cleanup(server.Close)

	client, err := NewOpenAI(OpenAIConfig{BaseURL: server.URL, Model: "m", MaxRetries: 3})
	if err != nil {
		t.Fatalf("NewOpenAI() error = %v", err)
	}

	_, err = client.Complete(context.Background(), domain.CompletionRequest{
		Messages: []domain.Message{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	if atomic.LoadInt32(&attempts) != 1 {
		t.Fatalf("attempts = %d, want 1 (validation errors must not be retried)", attempts)
	}
}

func TestCompleteHonorsContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(200 * time.Millisecond)
		_, _ = w.Write([]byte(`{"choices":[{"message":{"content":"late"}}]}`))
	}))
	t.Cleanup(server.Close)

	client, err := NewOpenAI(OpenAIConfig{BaseURL: server.URL, Model: "m", MaxRetries: 2})
	if err != nil {
		t.Fatalf("NewOpenAI() error = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, err := client.Complete(ctx, domain.CompletionRequest{
		Messages: []domain.Message{{Role: "user", Content: "hi"}},
	}); err == nil {
		t.Fatal("expected a cancelled request to fail")
	}
}

func TestCompleteReportsProviderError(t *testing.T) {
	client := newTestClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"error":{"message":"model not found"}}`))
	})
	_, err := client.Complete(context.Background(), domain.CompletionRequest{
		Messages: []domain.Message{{Role: "user", Content: "hi"}},
	})
	if err == nil {
		t.Fatal("expected an error")
	}
	var httpErr *httpError
	if errors.As(err, &httpErr) {
		t.Fatal("an error object inside a 200 response is not an HTTP error")
	}
}

func TestNewOpenAIRejectsInvalidConfig(t *testing.T) {
	if _, err := NewOpenAI(OpenAIConfig{Model: "m"}); err == nil {
		t.Fatal("expected missing base_url to be rejected")
	}
	if _, err := NewOpenAI(OpenAIConfig{BaseURL: "ftp://x", Model: "m"}); err == nil {
		t.Fatal("expected a non-HTTP scheme to be rejected")
	}
	if _, err := NewOpenAI(OpenAIConfig{BaseURL: "http://x"}); err == nil {
		t.Fatal("expected missing model to be rejected")
	}
}
