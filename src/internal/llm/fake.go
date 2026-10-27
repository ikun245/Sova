package llm

import (
	"context"
	"errors"
	"sync"

	"soc/agent/internal/domain"
)

// Fake is a scripted LLM for tests. It records every request so orchestration
// tests can assert which role was called with what context, without a network
// or a real provider.
type Fake struct {
	mu       sync.Mutex
	modelID  string
	queue    []fakeResult
	requests []domain.CompletionRequest
}

type fakeResult struct {
	response domain.CompletionResponse
	err      error
}

func NewFake(modelID string) *Fake {
	return &Fake{modelID: modelID}
}

// Queue appends one successful response, consumed in order.
func (f *Fake) Queue(response domain.CompletionResponse) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queue = append(f.queue, fakeResult{response: response})
}

// QueueError appends one failure, consumed in order.
func (f *Fake) QueueError(err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.queue = append(f.queue, fakeResult{err: err})
}

func (f *Fake) Model() string {
	return f.modelID
}

func (f *Fake) Complete(_ context.Context, req domain.CompletionRequest) (domain.CompletionResponse, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.requests = append(f.requests, req)
	if len(f.queue) == 0 {
		return domain.CompletionResponse{}, errors.New("fake llm: no queued response")
	}
	next := f.queue[0]
	f.queue = f.queue[1:]
	return next.response, next.err
}

// Requests returns a copy of every request in call order.
func (f *Fake) Requests() []domain.CompletionRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]domain.CompletionRequest, len(f.requests))
	copy(out, f.requests)
	return out
}

// Remaining reports how many scripted responses are left, which lets tests
// assert that no unexpected extra model call happened.
func (f *Fake) Remaining() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.queue)
}
