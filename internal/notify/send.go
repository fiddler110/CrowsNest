package notify

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"
)

// Channel limits on one message, in characters. Longer text is cut with an ellipsis rather than refused.
const (
	discordLimit = 2000
	ntfyLimit    = 4096
	webhookLimit = 4096
)

// truncate cuts s to at most max characters (not bytes), ending in "…" when it had to cut.
func truncate(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	return string(r[:max-1]) + "…"
}

// Status remembers whether the last send on each channel worked, so the dashboard can say when a channel is
// failing. The zero value is ready; a nil *Status ignores everything.
type Status struct {
	mu sync.Mutex
	ch map[string]ChannelStatus
}

// ChannelStatus is one channel's last outcome.
type ChannelStatus struct {
	Channel string    `json:"channel"`
	OK      bool      `json:"ok"`
	At      time.Time `json:"at"`
	Error   string    `json:"error,omitempty"`
}

func (s *Status) record(channel string, err error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ch == nil {
		s.ch = map[string]ChannelStatus{}
	}
	c := ChannelStatus{Channel: channel, OK: err == nil, At: time.Now()}
	if err != nil {
		c.Error = err.Error()
	}
	s.ch[channel] = c
}

// Failing lists the channels whose latest send failed.
func (s *Status) Failing() []ChannelStatus {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []ChannelStatus
	for _, c := range s.ch {
		if !c.OK {
			out = append(out, c)
		}
	}
	return out
}

// Healthy is false while any channel's latest send failed.
func (s *Status) Healthy() bool { return len(s.Failing()) == 0 }

// retry tunes deliver. The zero value means 3 attempts with 1s, 2s backoff.
type retry struct {
	Attempts int
	Base     time.Duration
	// MaxWait caps how long a Retry-After header can make us wait.
	MaxWait time.Duration
}

func (r retry) attempts() int {
	if r.Attempts > 0 {
		return r.Attempts
	}
	return 3
}

func (r retry) base() time.Duration {
	if r.Base > 0 {
		return r.Base
	}
	return time.Second
}

func (r retry) maxWait() time.Duration {
	if r.MaxWait > 0 {
		return r.MaxWait
	}
	return 10 * time.Second
}

// deliver sends the request build() makes, retrying network errors, 429 (honouring Retry-After) and 5xx with
// exponential backoff. Other 4xx answers are not retried. The outcome goes to status under name. Errors never
// carry the request URL: webhook URLs hold their token.
func deliver(ctx context.Context, name string, hc *http.Client, rt retry, status *Status, build func() (*http.Request, error)) {
	var err error
	for i := 0; i < rt.attempts(); i++ {
		var wait time.Duration
		var retryable bool
		wait, retryable, err = attempt(hc, build)
		if err == nil || !retryable || i == rt.attempts()-1 {
			break
		}
		if wait <= 0 {
			wait = rt.base() << i
		}
		if wait > rt.maxWait() {
			wait = rt.maxWait()
		}
		select {
		case <-ctx.Done():
			err = ctx.Err()
			i = rt.attempts()
		case <-time.After(wait):
		}
	}
	status.record(name, err)
	if err != nil {
		log.Printf("notify: %s: %v", name, err)
	}
}

func attempt(hc *http.Client, build func() (*http.Request, error)) (wait time.Duration, retryable bool, err error) {
	req, err := build()
	if err != nil {
		return 0, false, fmt.Errorf("build request: %w", err)
	}
	resp, err := hc.Do(req)
	if err != nil {
		return 0, true, fmt.Errorf("send: %w", redactURL(err))
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return 0, false, nil
	case resp.StatusCode == http.StatusTooManyRequests:
		if s, e := strconv.ParseFloat(resp.Header.Get("Retry-After"), 64); e == nil && s >= 0 {
			wait = time.Duration(s * float64(time.Second))
		}
		return wait, true, errors.New("rate limited (429)")
	case resp.StatusCode >= 500:
		return 0, true, fmt.Errorf("server error (%d)", resp.StatusCode)
	}
	return 0, false, fmt.Errorf("rejected (%d)", resp.StatusCode)
}

// redactURL returns err without the request URL a *url.Error embeds.
func redactURL(err error) error {
	var ue *url.Error
	if errors.As(err, &ue) {
		return fmt.Errorf("%s: %w", ue.Op, ue.Err)
	}
	return err
}

// Notifier is anything that can post a message.
type Notifier interface {
	Notify(ctx context.Context, message string)
}

// Multi sends every message to each of its notifiers at once.
type Multi []Notifier

// Notify implements Notifier.
func (m Multi) Notify(ctx context.Context, message string) {
	var wg sync.WaitGroup
	for _, n := range m {
		wg.Add(1)
		go func() { defer wg.Done(); n.Notify(ctx, message) }()
	}
	wg.Wait()
}
