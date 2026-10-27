package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"

	"soc/agent/internal/platform"
	"soc/agent/internal/store"
)

// runMigrate applies embedded migrations once, without starting the API.
func runMigrate() error {
	config, err := platform.LoadConfig()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	database, err := store.OpenPostgres(ctx, config.PostgresDSN)
	if err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	defer database.Close()

	if err := database.Migrate(); err != nil {
		return fmt.Errorf("run database migrations: %w", err)
	}
	slog.Info("migrations applied")
	return nil
}

// signalContext returns a context cancelled on SIGINT/SIGTERM.
func signalContext() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}
