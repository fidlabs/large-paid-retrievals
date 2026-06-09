package piecepayment

import (
	"net/http/httptest"
	"testing"
	"time"
)

func TestIPRateLimiterNilAllowsAll(t *testing.T) {
	var l *ipRateLimiter
	for i := 0; i < 1000; i++ {
		if !l.Allow("1.2.3.4") {
			t.Fatal("nil limiter must allow everything")
		}
	}
}

func TestIPRateLimiterDisabledOnNonPositive(t *testing.T) {
	if newIPRateLimiter(0, 10) != nil {
		t.Fatal("rps<=0 should disable")
	}
	if newIPRateLimiter(10, 0) != nil {
		t.Fatal("burst<=0 should disable")
	}
}

func TestIPRateLimiterBurstThenThrottleThenRefill(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter(2 /* rps */, 3 /* burst */)
	l.now = func() time.Time { return now }

	// Burst of 3 is allowed immediately.
	for i := 0; i < 3; i++ {
		if !l.Allow("9.9.9.9") {
			t.Fatalf("burst token %d should be allowed", i)
		}
	}
	// 4th in the same instant is throttled.
	if l.Allow("9.9.9.9") {
		t.Fatal("expected throttle after burst exhausted")
	}
	// After 1s at 2 rps, ~2 tokens refill.
	now = now.Add(time.Second)
	if !l.Allow("9.9.9.9") || !l.Allow("9.9.9.9") {
		t.Fatal("expected 2 refilled tokens after 1s")
	}
	if l.Allow("9.9.9.9") {
		t.Fatal("expected throttle once refilled tokens consumed")
	}
}

func TestIPRateLimiterPerIPIndependent(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter(1, 1)
	l.now = func() time.Time { return now }

	if !l.Allow("a") {
		t.Fatal("first IP should pass")
	}
	if !l.Allow("b") {
		t.Fatal("distinct IP must have its own bucket")
	}
	if l.Allow("a") {
		t.Fatal("same IP should now be throttled")
	}
}

func TestIPRateLimiterGCEvictsIdle(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	l := newIPRateLimiter(1, 1)
	l.now = func() time.Time { return now }

	l.Allow("stale")
	if len(l.buckets) != 1 {
		t.Fatalf("expected 1 bucket, got %d", len(l.buckets))
	}
	// Advance past the idle TTL and touch a different key to trigger GC.
	now = now.Add(quoteLimiterIdleTTL + time.Minute)
	l.Allow("fresh")
	if _, ok := l.buckets["stale"]; ok {
		t.Fatal("idle bucket should have been evicted by GC")
	}
	if _, ok := l.buckets["fresh"]; !ok {
		t.Fatal("fresh bucket should remain")
	}
}

func TestClientIP(t *testing.T) {
	r := httptest.NewRequest("GET", "/piece/x", nil)
	r.RemoteAddr = "203.0.113.7:54321"
	if got := clientIP(r); got != "203.0.113.7" {
		t.Fatalf("clientIP=%q want 203.0.113.7", got)
	}
	r.RemoteAddr = "no-port"
	if got := clientIP(r); got != "no-port" {
		t.Fatalf("clientIP fallback=%q want no-port", got)
	}
}
