package platform

import (
	"fmt"
	"net"
	"os"
	"strings"
	"time"
)

type Config struct {
	Address     string
	PostgresDSN string
	RedisAddr   string
	WorkerID    string
	// LeaseDuration bounds how long a claimed intent stays reserved for one
	// worker before another worker may take it over after a crash.
	LeaseDuration time.Duration
	// ExecBackend selects where authorized commands run: "local" runs them as
	// children of this process, "docker" runs them inside ToolboxContainer.
	ExecBackend string
	// ToolboxContainer is the long-lived Kali container used by the docker
	// backend. It is separate from the app image on purpose: scanners change
	// far more often than the platform, and a scanner compromise should not
	// automatically own the credential store.
	ToolboxContainer string
	// ToolboxWorkDir is the working directory inside the toolbox for tools that
	// write output or read wordlists.
	ToolboxWorkDir string
}

const (
	// ExecBackendLocal keeps everything on the host. It is the default so a
	// developer without Docker can still use the built-in HTTP tools.
	ExecBackendLocal = "local"
	// ExecBackendDocker sends binary commands to the Kali toolbox container.
	ExecBackendDocker = "docker"
)

func LoadConfig() (Config, error) {
	config := Config{
		Address:          envOr("SOC_ADDR", "127.0.0.1:8080"),
		PostgresDSN:      envOr("SOC_PG_DSN", "postgres://soc:soc-local-dev-only@127.0.0.1:5432/soc?sslmode=disable"),
		RedisAddr:        envOr("SOC_REDIS_ADDR", "127.0.0.1:6379"),
		WorkerID:         envOr("SOC_WORKER_ID", defaultWorkerID()),
		LeaseDuration:    envDurationOr("SOC_LEASE_DURATION", 2*time.Minute),
		ExecBackend:      strings.ToLower(envOr("SOC_EXEC_BACKEND", ExecBackendLocal)),
		ToolboxContainer: envOr("SOC_TOOLBOX_CONTAINER", "soc-toolbox"),
		ToolboxWorkDir:   envOr("SOC_TOOLBOX_WORKDIR", "/work"),
	}
	if _, _, err := net.SplitHostPort(config.Address); err != nil {
		return Config{}, fmt.Errorf("invalid SOC_ADDR %q: %w", config.Address, err)
	}
	if _, _, err := net.SplitHostPort(config.RedisAddr); err != nil {
		return Config{}, fmt.Errorf("invalid SOC_REDIS_ADDR %q: %w", config.RedisAddr, err)
	}
	if strings.TrimSpace(config.PostgresDSN) == "" {
		return Config{}, fmt.Errorf("SOC_PG_DSN must not be empty")
	}
	if config.LeaseDuration <= 0 {
		return Config{}, fmt.Errorf("SOC_LEASE_DURATION must be positive")
	}
	switch config.ExecBackend {
	case ExecBackendLocal, ExecBackendDocker:
	default:
		return Config{}, fmt.Errorf("SOC_EXEC_BACKEND must be %q or %q, got %q",
			ExecBackendLocal, ExecBackendDocker, config.ExecBackend)
	}
	if config.ExecBackend == ExecBackendDocker && strings.TrimSpace(config.ToolboxContainer) == "" {
		return Config{}, fmt.Errorf("SOC_TOOLBOX_CONTAINER is required when SOC_EXEC_BACKEND=docker")
	}
	return config, nil
}

func envOr(key, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(key)); value != "" {
		return value
	}
	return fallback
}

func envDurationOr(key string, fallback time.Duration) time.Duration {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return fallback
	}
	return value
}

func defaultWorkerID() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "unknown-host"
	}
	return fmt.Sprintf("%s-%d", host, os.Getpid())
}
