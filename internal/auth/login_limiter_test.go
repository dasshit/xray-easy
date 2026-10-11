package auth

import (
	"testing"
	"time"
)

func TestLoginLimiterEnforcesPerSourceWindowAndExpiresEntries(t *testing.T) {
	limiter := NewLoginLimiter(2, time.Minute, 1, 2)
	now := time.Date(2026, 10, 5, 12, 0, 0, 0, time.UTC)
	limiter.now = func() time.Time { return now }
	for attempt := 0; attempt < 2; attempt++ {
		if allowed, _ := limiter.Allow("192.0.2.1"); !allowed {
			t.Fatalf("attempt %d was unexpectedly denied", attempt+1)
		}
	}
	if allowed, retry := limiter.Allow("192.0.2.1"); allowed || retry != time.Minute {
		t.Fatalf("exhausted source allowance = %v, %v; want false, 1m", allowed, retry)
	}
	if allowed, _ := limiter.Allow("192.0.2.2"); !allowed {
		t.Fatal("second source was denied before source table filled")
	}
	if allowed, _ := limiter.Allow("192.0.2.3"); allowed {
		t.Fatal("source table exceeded its configured bound")
	}
	now = now.Add(time.Minute)
	if allowed, _ := limiter.Allow("192.0.2.3"); !allowed {
		t.Fatal("expired windows were not removed")
	}
}

func TestLoginLimiterBoundsConcurrentVerifications(t *testing.T) {
	limiter := NewLoginLimiter(10, time.Minute, 1, 10)
	if !limiter.AcquireVerification() {
		t.Fatal("first verification slot was not available")
	}
	if limiter.AcquireVerification() {
		t.Fatal("verification pool exceeded its configured concurrency")
	}
	limiter.ReleaseVerification()
	if !limiter.AcquireVerification() {
		t.Fatal("released verification slot was not reusable")
	}
	limiter.ReleaseVerification()
	limiter.ReleaseVerification()
	if !limiter.AcquireVerification() {
		t.Fatal("extra release corrupted verification capacity")
	}
}

func TestLoginLimiterUsesSafeDefaultsAndNilReceiver(t *testing.T) {
	var limiter *LoginLimiter
	if allowed, retry := limiter.Allow(""); !allowed || retry != 0 || !limiter.AcquireVerification() {
		t.Fatal("nil limiter should permit requests")
	}
	limiter.ReleaseVerification()
	limiter = NewLoginLimiter(0, 0, 0, 0)
	if allowed, _ := limiter.Allow("source"); !allowed {
		t.Fatal("default limiter denied its first request")
	}
	if !limiter.AcquireVerification() {
		t.Fatal("default limiter has no verification capacity")
	}
	limiter.ReleaseVerification()
}
