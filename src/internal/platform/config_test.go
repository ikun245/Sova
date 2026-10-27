package platform

import "testing"

func TestLoadConfigRejectsInvalidAddress(t *testing.T) {
	t.Setenv("SOC_ADDR", "not-an-address")
	if _, err := LoadConfig(); err == nil {
		t.Fatal("expected invalid address to be rejected")
	}
}

func TestLoadConfigUsesDefaults(t *testing.T) {
	t.Setenv("SOC_ADDR", "")
	t.Setenv("SOC_PG_DSN", "")

	config, err := LoadConfig()
	if err != nil {
		t.Fatalf("LoadConfig() error = %v", err)
	}
	if config.Address != "127.0.0.1:8080" {
		t.Fatalf("Address = %q, want default address", config.Address)
	}
	if config.PostgresDSN == "" {
		t.Fatal("PostgresDSN should have a local development default")
	}
}
