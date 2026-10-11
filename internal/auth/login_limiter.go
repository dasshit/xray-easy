package auth

import (
	"strings"
	"sync"
	"time"
)

type loginAttemptWindow struct {
	started time.Time
	count   int
}

// LoginLimiter bounds authentication attempts per source and caps concurrent
// password hashes, whose Argon2 memory cost is intentionally high.
type LoginLimiter struct {
	mu            sync.Mutex
	attempts      map[string]loginAttemptWindow
	limit         int
	window        time.Duration
	maxSources    int
	now           func() time.Time
	verifications chan struct{}
}

// NewLoginLimiter constructs a bounded source limiter and password-hash gate.
func NewLoginLimiter(limit int, window time.Duration, maxConcurrent, maxSources int) *LoginLimiter {
	if limit < 1 {
		limit = 10
	}
	if window <= 0 {
		window = time.Minute
	}
	if maxConcurrent < 1 {
		maxConcurrent = 2
	}
	if maxSources < 1 {
		maxSources = 4096
	}
	return &LoginLimiter{
		attempts:      make(map[string]loginAttemptWindow),
		limit:         limit,
		window:        window,
		maxSources:    maxSources,
		now:           time.Now,
		verifications: make(chan struct{}, maxConcurrent),
	}
}

// Allow records an authentication attempt and reports how long the source
// should wait when its fixed window is exhausted.
func (l *LoginLimiter) Allow(source string) (bool, time.Duration) {
	if l == nil {
		return true, 0
	}
	source = strings.TrimSpace(source)
	if source == "" {
		source = "unknown"
	}
	now := l.now()
	l.mu.Lock()
	defer l.mu.Unlock()
	for key, window := range l.attempts {
		if now.Sub(window.started) >= l.window {
			delete(l.attempts, key)
		}
	}
	window, exists := l.attempts[source]
	if exists && now.Sub(window.started) < l.window {
		if window.count >= l.limit {
			return false, l.window - now.Sub(window.started)
		}
		window.count++
		l.attempts[source] = window
		return true, 0
	}
	if len(l.attempts) >= l.maxSources {
		return false, l.window
	}
	l.attempts[source] = loginAttemptWindow{started: now, count: 1}
	return true, 0
}

// AcquireVerification enters the bounded Argon2 verification pool without
// blocking an HTTP handler behind other expensive requests.
func (l *LoginLimiter) AcquireVerification() bool {
	if l == nil {
		return true
	}
	select {
	case l.verifications <- struct{}{}:
		return true
	default:
		return false
	}
}

// ReleaseVerification frees one Argon2 verification slot.
func (l *LoginLimiter) ReleaseVerification() {
	if l == nil {
		return
	}
	select {
	case <-l.verifications:
	default:
	}
}
