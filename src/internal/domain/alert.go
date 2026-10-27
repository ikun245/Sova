package domain

import (
	"encoding/json"
	"time"
)

const LocalTenantID = "local"

type AlertStatus string

const AlertStatusReceived AlertStatus = "received"

type Alert struct {
	ID         string          `json:"id"`
	TenantID   string          `json:"tenant_id,omitempty"`
	Source     string          `json:"source"`
	Raw        json.RawMessage `json:"raw"`
	DedupKey   string          `json:"-"`
	Status     AlertStatus     `json:"status"`
	ReceivedAt time.Time       `json:"received_at"`
}
