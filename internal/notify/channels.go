package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

func httpClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Ntfy publishes to an ntfy topic URL (https://ntfy.sh/<topic> or a self-hosted one). Token, when set, is sent as a
// bearer token for protected topics. The zero value is inert.
type Ntfy struct {
	URL, Token string
	HTTPClient *http.Client
	Status     *Status
	retry      retry
}

// Notify implements Notifier.
func (n *Ntfy) Notify(ctx context.Context, message string) {
	if n == nil || strings.TrimSpace(n.URL) == "" {
		return
	}
	deliver(ctx, "ntfy", httpClient(n.HTTPClient), n.retry, n.Status, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.URL, strings.NewReader(truncate(message, ntfyLimit)))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Title", "CrowsNest")
		if n.Token != "" {
			req.Header.Set("Authorization", "Bearer "+n.Token)
		}
		return req, nil
	})
}

// Webhook posts {"text": "..."} as JSON to any URL (Slack-compatible, and easy to point at Home Assistant, n8n
// and the like). The zero value is inert.
type Webhook struct {
	URL        string
	HTTPClient *http.Client
	Status     *Status
	retry      retry
}

// Notify implements Notifier.
func (w *Webhook) Notify(ctx context.Context, message string) {
	if w == nil || strings.TrimSpace(w.URL) == "" {
		return
	}
	body, _ := json.Marshal(map[string]string{"text": truncate(message, webhookLimit)})
	deliver(ctx, "webhook", httpClient(w.HTTPClient), w.retry, w.Status, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.URL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
}
