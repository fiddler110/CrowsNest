package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Limiter is an in-memory sliding-window rate limiter keyed by an arbitrary
// string (typically a client IP). Not distributed — fine for a single
// CrowsNest instance, which is the only deployment shape this project has.
type Limiter struct {
	mu     sync.Mutex
	window time.Duration
	max    int
	hits   map[string][]time.Time
}

func NewLimiter(max int, window time.Duration) *Limiter {
	return &Limiter{window: window, max: max, hits: make(map[string][]time.Time)}
}

// Allow reports whether key is still under the limit, recording this
// attempt if so.
func (l *Limiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.window)
	kept := l.hits[key][:0]
	for _, t := range l.hits[key] {
		if t.After(cutoff) {
			kept = append(kept, t)
		}
	}
	if len(kept) >= l.max {
		l.hits[key] = kept
		return false
	}
	l.hits[key] = append(kept, now)
	return true
}

// Prune drops every tracked key with no hits inside the current window.
// Allow already trims stale hits off a key each time that key is seen
// again, but a key that's hit once and never revisited (e.g. a one-off
// probe from a source IP that never comes back) would otherwise sit in the
// map forever — Prune bounds that.
func (l *Limiter) Prune() {
	l.mu.Lock()
	defer l.mu.Unlock()

	cutoff := time.Now().Add(-l.window)
	for key, hits := range l.hits {
		stale := true
		for _, t := range hits {
			if t.After(cutoff) {
				stale = false
				break
			}
		}
		if stale {
			delete(l.hits, key)
		}
	}
}

// RunPruner calls Prune every interval until ctx is cancelled. Meant to be
// started in its own goroutine for the lifetime of the process.
func (l *Limiter) RunPruner(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			l.Prune()
		}
	}
}

// ParseTrustedProxies converts CIDR strings into net.IPNets for ClientIP.
func ParseTrustedProxies(cidrs []string) ([]*net.IPNet, error) {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("auth: invalid trusted proxy CIDR %q: %w", cidr, err)
		}
		nets = append(nets, n)
	}
	return nets, nil
}

// ClientIP returns the request's client IP, honoring X-Forwarded-For only
// when RemoteAddr belongs to one of trustedProxies. This prevents a
// client from spoofing its rate-limit key via a forged header when no
// trusted reverse proxy is in front of CrowsNest.
func ClientIP(r *http.Request, trustedProxies []*net.IPNet) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	remoteIP := net.ParseIP(host)

	if remoteIP != nil && isTrusted(remoteIP, trustedProxies) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			// Walk from the right: a proxy appends the address it saw, so
			// only the entries after the last untrusted hop are reliable;
			// anything further left the client may have forged.
			parts := strings.Split(xff, ",")
			for i := len(parts) - 1; i >= 0; i-- {
				ip := net.ParseIP(strings.TrimSpace(parts[i]))
				if ip == nil {
					break
				}
				if !isTrusted(ip, trustedProxies) {
					return ip.String()
				}
			}
		}
	}
	return host
}

func isTrusted(ip net.IP, trusted []*net.IPNet) bool {
	for _, n := range trusted {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}
