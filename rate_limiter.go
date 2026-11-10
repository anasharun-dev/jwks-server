package main

import (
	"sync"
	"time"
)

type rateWindow struct {
	started time.Time
	count   int
}

type ipRateLimiter struct {
	mu      sync.Mutex
	limit   int
	window  time.Duration
	clients map[string]rateWindow
}

func newIPRateLimiter(limit int, window time.Duration) *ipRateLimiter {
	return &ipRateLimiter{limit: limit, window: window, clients: make(map[string]rateWindow)}
}

func (l *ipRateLimiter) allow(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	entry, found := l.clients[ip]
	if !found || now.Sub(entry.started) >= l.window || now.Before(entry.started) {
		l.clients[ip] = rateWindow{started: now, count: 1}
		return true
	}
	if entry.count >= l.limit {
		return false
	}
	entry.count++
	l.clients[ip] = entry
	return true
}
