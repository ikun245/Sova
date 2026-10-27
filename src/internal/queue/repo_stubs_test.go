package queue

import (
	"context"

	"soc/agent/internal/domain"
)

// Test doubles need the full TaskRepository surface. ListTaskEvents returns
// nothing because these tests exercise the handler, not the planner.
func (f *failingTaskRepo) ListTaskEvents(context.Context, string, int) ([]domain.TaskEvent, error) {
	return nil, nil
}

func (s *scriptedRepo) ListTaskEvents(context.Context, string, int) ([]domain.TaskEvent, error) {
	return nil, nil
}

func (r *leaseRepo) ListTaskEvents(context.Context, string, int) ([]domain.TaskEvent, error) {
	return nil, nil
}
