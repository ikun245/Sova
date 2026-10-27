package exec

import (
	"context"
	"sync"
	"time"
)

// RateLimiter spaces requests evenly so a batch scanner cannot turn into a
// denial-of-service against the target.
//
// Even spacing is chosen over a bursty token bucket on purpose: a target sees
// a predictable cadence, which is both gentler and easier to explain in a
// report. A zero rate means "unlimited" and returns a nil limiter.
type RateLimiter struct {
	mu       sync.Mutex
	interval time.Duration
	next     time.Time
	// now and sleep are injectable so tests do not spend real seconds.
	now   func() time.Time
	sleep func(context.Context, time.Duration) error
}

// NewRateLimiter builds a limiter for at most perMinute requests. It returns
// nil when perMinute is not positive, so callers need no special case.
func NewRateLimiter(perMinute int) *RateLimiter {
	if perMinute <= 0 {
		return nil
	}
	return &RateLimiter{
		interval: time.Minute / time.Duration(perMinute),
		now:      time.Now,
		sleep:    sleepCtx,
	}
}

// Wait blocks until the next slot is available. Cancellation returns the
// context error so a shutdown never leaves a goroutine spinning.
func (l *RateLimiter) Wait(ctx context.Context) error {
	if l == nil {
		return nil
	}

	l.mu.Lock()
	now := l.now()
	slot := l.next
	if slot.Before(now) {
		slot = now
	}
	l.next = slot.Add(l.interval)
	l.mu.Unlock()

	delay := slot.Sub(now)
	if delay <= 0 {
		return nil
	}
	return l.sleep(ctx, delay)
}

// Interval reports the spacing, useful for logging the effective policy.
func (l *RateLimiter) Interval() time.Duration {
	if l == nil {
		return 0
	}
	return l.interval
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
