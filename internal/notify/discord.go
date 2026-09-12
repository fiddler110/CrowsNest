// Package notify sends outbound notifications about CrowsNest-initiated
// events (currently: idle-shutdown and night-shutdown stopping a game) to
// external services. Direct port of the original Python CrowsNest's
// send_discord_notification() (app.py lines ~731-748), generalized so any
// caller can send a message without knowing whether notifications are
// actually configured.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

const discordWebhookPrefix = "https://discord.com/api/webhooks/"

// Discord posts plain-text messages to a Discord webhook. The zero value is
// a valid, inert Notifier: Notify is a silent no-op until WebhookURL is
// set, so callers can construct one unconditionally at startup rather than
// branching on whether notifications are configured.
type Discord struct {
	WebhookURL string
	HTTPClient *http.Client
}

func (d *Discord) client() *http.Client {
	if d.HTTPClient != nil {
		return d.HTTPClient
	}
	return &http.Client{Timeout: 10 * time.Second}
}

// Notify posts message to the configured webhook. It never returns an
// error — a failed or unconfigured notification should never fail the
// stop it's reporting on — and instead logs anything worth knowing about.
func (d *Discord) Notify(ctx context.Context, message string) {
	if d == nil || strings.TrimSpace(d.WebhookURL) == "" {
		return
	}
	if !strings.HasPrefix(d.WebhookURL, discordWebhookPrefix) {
		log.Printf("notify: webhook URL does not look like a Discord webhook URL — skipping")
		return
	}

	body, err := json.Marshal(map[string]string{"content": message})
	if err != nil {
		log.Printf("notify: encode message: %v", err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.WebhookURL, bytes.NewReader(body))
	if err != nil {
		log.Printf("notify: build request: %v", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := d.client().Do(req)
	if err != nil {
		log.Printf("notify: send Discord webhook: %v", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusNoContent {
		log.Printf("notify: Discord webhook returned %d", resp.StatusCode)
	}
}
