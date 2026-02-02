package server

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const ipRateLimiterTTL = 10 * time.Minute

type ipRateLimiter struct {
	mu          sync.Mutex
	rate        float64
	burst       float64
	entries     map[string]*ipRateEntry
	lastCleanup time.Time
}

type ipRateEntry struct {
	tokens float64
	last   time.Time
}

func newIPRateLimiter(perSec int, burst int) *ipRateLimiter {
	if perSec <= 0 {
		return nil
	}
	if burst <= 0 {
		burst = perSec
	}
	return &ipRateLimiter{
		rate:        float64(perSec),
		burst:       float64(burst),
		entries:     make(map[string]*ipRateEntry),
		lastCleanup: time.Now(),
	}
}

func (l *ipRateLimiter) Allow(ip string) bool {
	if l == nil || ip == "" {
		return true
	}
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()

	entry := l.entries[ip]
	if entry == nil {
		entry = &ipRateEntry{tokens: l.burst, last: now}
		l.entries[ip] = entry
	}
	elapsed := now.Sub(entry.last).Seconds()
	if elapsed > 0 {
		entry.tokens += elapsed * l.rate
		if entry.tokens > l.burst {
			entry.tokens = l.burst
		}
		entry.last = now
	}

	if entry.tokens < 1 {
		l.cleanupLocked(now)
		return false
	}
	entry.tokens -= 1
	l.cleanupLocked(now)
	return true
}

func (l *ipRateLimiter) cleanupLocked(now time.Time) {
	if now.Sub(l.lastCleanup) < ipRateLimiterTTL {
		return
	}
	cutoff := now.Add(-ipRateLimiterTTL)
	for ip, entry := range l.entries {
		if entry == nil || entry.last.Before(cutoff) {
			delete(l.entries, ip)
		}
	}
	l.lastCleanup = now
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-For")); forwarded != "" {
		parts := strings.Split(forwarded, ",")
		if len(parts) > 0 {
			ip := strings.TrimSpace(parts[0])
			if ip != "" {
				return ip
			}
		}
	}
	if realIP := strings.TrimSpace(r.Header.Get("X-Real-IP")); realIP != "" {
		return realIP
	}
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil && host != "" {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}
