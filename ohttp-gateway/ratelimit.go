package main

import (
	"sync"
	"time"
)

// globalRateLimiter is a simple, dependency-free token bucket that bounds the
// TOTAL outbound request rate this gateway process will make to upstream
// targets. It exists so a shared upstream budget (an origin that rate-limits by
// credential rather than per-client) cannot be exhausted by many simultaneous
// clients funnelling through one gateway.
//
// It is deliberately per-process and in-memory: when a deployment runs N gateway
// replicas, configure each replica's limit to the global budget divided by N.
// This keeps the mechanism generic and stateless — no shared store, no external
// dependency — at the cost of some slack when load is uneven across replicas.
//
// Disabled by default: newGlobalRateLimiter returns nil when the configured
// rate is not positive, and a nil *globalRateLimiter always allows, so the
// limiter has zero effect unless an operator opts in via configuration.
type globalRateLimiter struct {
	mu           sync.Mutex
	tokens       float64
	maxTokens    float64
	refillPerSec float64
	last         time.Time
}

// newGlobalRateLimiter builds a limiter allowing up to qpm requests per minute
// with a burst of one minute's worth of tokens. A non-positive qpm disables the
// limiter (returns nil).
func newGlobalRateLimiter(qpm int) *globalRateLimiter {
	if qpm <= 0 {
		return nil
	}
	max := float64(qpm)
	return &globalRateLimiter{
		tokens:       max,
		maxTokens:    max,
		refillPerSec: max / 60.0,
		last:         time.Now(),
	}
}

// allow reports whether a request may proceed, consuming one token if so. A nil
// receiver always allows, so callers need not branch on whether a limiter is
// configured.
func (l *globalRateLimiter) allow() bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(l.last).Seconds()
	l.last = now
	l.tokens += elapsed * l.refillPerSec
	if l.tokens > l.maxTokens {
		l.tokens = l.maxTokens
	}
	if l.tokens >= 1 {
		l.tokens--
		return true
	}
	return false
}

// retryAfterSeconds returns a conservative whole-second hint for how long a
// caller should wait before retrying when a request was refused. It is a hint,
// not a guarantee (other callers also consume the refill).
func (l *globalRateLimiter) retryAfterSeconds() int {
	if l == nil || l.refillPerSec <= 0 {
		return 1
	}
	secs := int(1.0/l.refillPerSec + 0.999)
	if secs < 1 {
		secs = 1
	}
	return secs
}
