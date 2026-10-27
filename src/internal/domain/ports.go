package domain

import "context"

type AlertRepository interface {
	CreateAlert(ctx context.Context, alert Alert) (Alert, error)
	ListAlerts(ctx context.Context, tenantID string, limit int) ([]Alert, error)
}
