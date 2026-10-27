package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"time"

	"soc/agent/internal/api"
	"soc/agent/internal/app"
	"soc/agent/internal/platform"
	"soc/agent/internal/store"
)

const version = "0.1.0-dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		slog.Error("soc command failed", "error", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		return errors.New("usage: soc <api|migrate|worker|version>")
	}

	switch args[0] {
	case "version":
		fmt.Println(version)
		return nil
	case "migrate":
		return runMigrate()
	case "worker":
		return runWorker()
	case "models":
		return runModels(args[1:])
	case "probe":
		return runProbe(args[1:])
	case "web":
		return runWeb(args[1:])
	case "hunt":
		return runHunt(args[1:])
	case "team":
		return runTeam(args[1:])
	case "api":
		return runAPI()
	default:
		return fmt.Errorf("unknown command %q; usage: soc <api|hunt|migrate|models|probe|team|web|worker|version>", args[0])
	}
}

func runAPI() error {
	config, err := platform.LoadConfig()
	if err != nil {
		return err
	}

	startupCtx, cancelStartup := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancelStartup()

	database, err := store.OpenPostgres(startupCtx, config.PostgresDSN)
	if err != nil {
		return fmt.Errorf("connect to PostgreSQL: %w", err)
	}
	defer database.Close()

	if err := database.Migrate(); err != nil {
		return fmt.Errorf("run database migrations: %w", err)
	}

	server := &http.Server{
		Addr: config.Address,
		Handler: api.NewRouter(app.NewAlerts(database), database.Ping, api.RouterDeps{
			Scopes:   database,
			Tasks:    database,
			Findings: database,
		}),
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	serverErrors := make(chan error, 1)
	go func() {
		slog.Info("API listening", "address", config.Address, "version", version)
		serverErrors <- server.ListenAndServe()
	}()

	shutdownCtx, stop := signalContext()
	defer stop()

	select {
	case err := <-serverErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	case <-shutdownCtx.Done():
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := server.Shutdown(ctx); err != nil {
		return fmt.Errorf("shut down API: %w", err)
	}
	return nil
}
