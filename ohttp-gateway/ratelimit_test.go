package main

import "testing"

func TestGlobalRateLimiterDisabledWhenNonPositive(t *testing.T) {
	if l := newGlobalRateLimiter(0); l != nil {
		t.Fatalf("qpm=0 should disable the limiter, got non-nil")
	}
	if l := newGlobalRateLimiter(-5); l != nil {
		t.Fatalf("negative qpm should disable the limiter, got non-nil")
	}
}

func TestNilLimiterAlwaysAllows(t *testing.T) {
	var l *globalRateLimiter // nil
	for i := 0; i < 1000; i++ {
		if !l.allow() {
			t.Fatalf("nil limiter must always allow")
		}
	}
}

func TestBurstThenRefusal(t *testing.T) {
	// 60 qpm => burst of 60 tokens, refill 1/sec. The first 60 immediate calls
	// should pass; the 61st (before any refill) should be refused.
	l := newGlobalRateLimiter(60)
	allowed := 0
	for i := 0; i < 60; i++ {
		if l.allow() {
			allowed++
		}
	}
	if allowed != 60 {
		t.Fatalf("expected full burst of 60 to pass, got %d", allowed)
	}
	if l.allow() {
		t.Fatalf("61st immediate call should be refused (bucket empty)")
	}
	if got := l.retryAfterSeconds(); got < 1 {
		t.Fatalf("retryAfterSeconds must be >=1, got %d", got)
	}
}
