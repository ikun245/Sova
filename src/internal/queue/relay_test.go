package queue

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/hibiken/asynq"

	"soc/agent/internal/domain"
)

type outboxStub struct {
	published []int64
	failed    map[int64]string
	nextItems []domain.OutboxItem
}

func (s *outboxStub) PublishPending(context.Context, int) ([]domain.OutboxItem, error) {
	items := s.nextItems
	s.nextItems = nil
	return items, nil
}

func (s *outboxStub) MarkPublished(_ context.Context, ids []int64) error {
	s.published = append(s.published, ids...)
	return nil
}

func (s *outboxStub) MarkFailed(_ context.Context, id int64, reason string) error {
	if s.failed == nil {
		s.failed = map[int64]string{}
	}
	s.failed[id] = reason
	return nil
}

type recordingEnqueuer struct {
	tasks []string
	err   error
}

func (s *recordingEnqueuer) EnqueueTask(_ context.Context, taskID string, _ ...asynq.Option) error {
	if s.err != nil {
		return s.err
	}
	s.tasks = append(s.tasks, taskID)
	return nil
}

func TestRelayPublishesTaskQueuedMessage(t *testing.T) {
	payload, err := json.Marshal(map[string]string{"task_id": "task-1", "alert_id": "alert-1"})
	if err != nil {
		t.Fatal(err)
	}
	outbox := &outboxStub{nextItems: []domain.OutboxItem{
		{ID: 1, Topic: TopicTaskQueued, Payload: payload},
	}}
	enqueuer := &recordingEnqueuer{}
	relay := NewRelay(outbox, enqueuer)

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain() error = %v", err)
	}
	if len(enqueuer.tasks) != 1 || enqueuer.tasks[0] != "task-1" {
		t.Fatalf("enqueued = %v, want [task-1]", enqueuer.tasks)
	}
	if len(outbox.published) != 1 || outbox.published[0] != 1 {
		t.Fatalf("published = %v, want [1]", outbox.published)
	}
}

func TestRelayMarksFailureAndDoesNotPublish(t *testing.T) {
	payload, err := json.Marshal(map[string]string{"task_id": "task-2"})
	if err != nil {
		t.Fatal(err)
	}
	outbox := &outboxStub{nextItems: []domain.OutboxItem{
		{ID: 7, Topic: TopicTaskQueued, Payload: payload},
	}}
	enqueuer := &recordingEnqueuer{err: errors.New("redis down")}
	relay := NewRelay(outbox, enqueuer)

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain() error = %v", err)
	}
	if _, ok := outbox.failed[7]; !ok {
		t.Fatal("failed message must be recorded for retry")
	}
	if len(outbox.published) != 0 {
		t.Fatalf("published = %v, want none", outbox.published)
	}
}

func TestRelayRejectsUnknownTopic(t *testing.T) {
	outbox := &outboxStub{nextItems: []domain.OutboxItem{
		{ID: 9, Topic: "unknown.topic", Payload: json.RawMessage(`{}`)},
	}}
	relay := NewRelay(outbox, &recordingEnqueuer{})

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain() error = %v", err)
	}
	if _, ok := outbox.failed[9]; !ok {
		t.Fatal("unknown topic must be marked failed instead of silently dropped")
	}
}

func TestRelayRejectsPayloadWithoutTaskID(t *testing.T) {
	outbox := &outboxStub{nextItems: []domain.OutboxItem{
		{ID: 11, Topic: TopicTaskQueued, Payload: json.RawMessage(`{"alert_id":"a"}`)},
	}}
	relay := NewRelay(outbox, &recordingEnqueuer{})

	if err := relay.Drain(context.Background()); err != nil {
		t.Fatalf("Drain() error = %v", err)
	}
	if _, ok := outbox.failed[11]; !ok {
		t.Fatal("missing task_id must be marked failed")
	}
}
