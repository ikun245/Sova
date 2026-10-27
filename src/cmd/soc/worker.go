package main

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/hibiken/asynq"

	"soc/agent/internal/platform"
	"soc/agent/internal/queue"
	"soc/agent/internal/store"
)

func runWorker() error {
	config, err := platform.LoadConfig()
	if err != nil {
		return err
	}

	ctx, stop := signalContext()
	defer stop()

	startupCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	database, err := store.OpenPostgres(startupCtx, config.PostgresDSN)
	if err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	defer database.Close()

	if err := database.Migrate(); err != nil {
		return fmt.Errorf("run database migrations: %w", err)
	}

	// Recover work left behind by a crashed worker before consuming new tasks.
	if recovered, err := database.RecoverExpiredLeases(startupCtx); err != nil {
		return fmt.Errorf("recover expired leases: %w", err)
	} else if recovered > 0 {
		slog.Info("returned expired intents to pending", "count", recovered)
	}
	if closed, err := database.FinishIdleTasks(startupCtx); err != nil {
		return fmt.Errorf("finish idle tasks: %w", err)
	} else if closed > 0 {
		slog.Info("closed tasks with no open intents", "count", closed)
	}

	// The relay moves committed outbox rows into Redis. Losing a Redis message
	// is recoverable because the durable task state and outbox remain in
	// PostgreSQL.
	enqueuer := queue.NewAsynqEnqueuer(config.RedisAddr)
	defer func() { _ = enqueuer.Close() }()

	relay := queue.NewRelay(database, enqueuer)
	relayErrors := make(chan error, 1)
	go func() {
		relayErrors <- relay.Run(ctx, 500*time.Millisecond)
	}()

	server := asynq.NewServer(
		asynq.RedisClientOpt{Addr: config.RedisAddr},
		asynq.Config{Concurrency: 4},
	)
	handler := queue.NewTriageHandler(database, config.LeaseDuration)
	handler.SetVerdicts(database)

	// Model-backed work is optional: without a models file the worker still
	// processes intents, it just cannot judge alerts or summon a team. This
	// keeps local development working with no credentials.
	runtime, err := buildAgentRuntime(database)
	if err != nil {
		return err
	}
	if runtime != nil {
		handler.SetExecutor(runtime.executor)
		handler.SetConsultation(runtime.consultation)
	} else {
		slog.Info("agent runtime disabled: set SOC_MODELS_CONFIG to enable triage and consultation")
	}

	mux := asynq.NewServeMux()
	mux.HandleFunc(queue.TaskTypeTriage, func(ctx context.Context, task *asynq.Task) error {
		return handler.Handle(queue.WithWorkerID(ctx, config.WorkerID), task)
	})

	if err := server.Start(mux); err != nil {
		return fmt.Errorf("start worker: %w", err)
	}
	slog.Info("worker started", "worker_id", config.WorkerID, "redis", config.RedisAddr)

	select {
	case err := <-relayErrors:
		server.Shutdown()
		if err != nil {
			return fmt.Errorf("outbox relay: %w", err)
		}
		return nil
	case <-ctx.Done():
	}

	slog.Info("worker shutting down")
	server.Shutdown()
	return nil
}
