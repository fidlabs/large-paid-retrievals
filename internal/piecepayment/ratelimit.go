package piecepayment

import (
	"net"
	"net/http"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// quoteLimiterIdleTTL is how long an idle per-IP bucket is retained before GC.
const quoteLimiterIdleTTL = 10 * time.Minute

// ipRateLimiter is a per-client-IP token-bucket limiter used to bound the
// unauthenticated quote path (upstream HEAD probe + quote insert), which is
// otherwise a free amplification vector — every anonymous GET issues one HEAD to
// the upstream piece server and one DB write. Authenticated/paid retries carry an
// Authorization header and bypass this limiter, so resumable and parallel/range
// paid downloads within the paid-access window are unaffected.
//
// A nil *ipRateLimiter allows everything (limiting disabled). Buckets are keyed by
// the TCP peer IP (not spoofable over a completed TCP handshake) and swept after
// quoteLimiterIdleTTL of inactivity to bound memory.
type ipRateLimiter struct {
	rps   rate.Limit
	burst int
	now   func() time.Time

	mu      sync.Mutex
	buckets map[string]*ipBucket
	lastGC  time.Time
}

type ipBucket struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// newIPRateLimiter returns a limiter, or nil if rps or burst is non-positive
// (limiting disabled).
func newIPRateLimiter(rps float64, burst int) *ipRateLimiter {
	if rps <= 0 || burst <= 0 {
		return nil
	}
	return &ipRateLimiter{
		rps:     rate.Limit(rps),
		burst:   burst,
		now:     time.Now,
		buckets: make(map[string]*ipBucket),
	}
}

// Allow reports whether a request from key (a client IP) may proceed. It consumes
// one token on success. A nil limiter always allows.
func (l *ipRateLimiter) Allow(key string) bool {
	if l == nil {
		return true
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	l.gcLocked(now)
	b, ok := l.buckets[key]
	if !ok {
		b = &ipBucket{limiter: rate.NewLimiter(l.rps, l.burst)}
		l.buckets[key] = b
	}
	b.lastSeen = now
	return b.limiter.AllowN(now, 1)
}

// gcLocked sweeps idle buckets at most once per idle TTL. Caller holds l.mu.
func (l *ipRateLimiter) gcLocked(now time.Time) {
	if now.Sub(l.lastGC) < quoteLimiterIdleTTL {
		return
	}
	l.lastGC = now
	for k, b := range l.buckets {
		if now.Sub(b.lastSeen) >= quoteLimiterIdleTTL {
			delete(l.buckets, k)
		}
	}
}

// clientIP extracts the TCP peer IP from r.RemoteAddr, falling back to the raw
// value if it has no port. X-Forwarded-For is intentionally ignored: these
// services are fetched direct by IP, and trusting a client header would let
// callers trivially evade the per-IP limit.
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
