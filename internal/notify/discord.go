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
	"errors"
	"log"
	"net/http"
	"strings"
)

const discordWebhookPrefix = "https://discord.com/api/webhooks/"

// Discord posts plain-text messages to a Discord webhook. The zero value is
// a valid, inert Notifier: Notify is a silent no-op until WebhookURL is
// set, so callers can construct one unconditionally at startup rather than
// branching on whether notifications are configured.
type Discord struct {
	WebhookURL string
	HTTPClient *http.Client
	// Status, when set, records whether the last send worked.
	Status *Status
	// Mentions, when set, lists the Discord user ids to ping for a notice about a game (see WithGame).
	Mentions *Mentions
	retry    retry
}

// Notify posts message (cut to Discord's 2,000 characters) to the configured webhook, retrying rate limits, server
// errors and network failures with backoff. It never returns an error: a failed or unconfigured notification should
// never fail the stop it's reporting on. A failure is logged and recorded in Status.
func (d *Discord) Notify(ctx context.Context, message string) {
	if d == nil || strings.TrimSpace(d.WebhookURL) == "" {
		return
	}
	if !strings.HasPrefix(d.WebhookURL, discordWebhookPrefix) {
		log.Printf("notify: webhook URL does not look like a Discord webhook URL — skipping")
		d.Status.record("discord", errors.New("the webhook URL is not a Discord webhook URL"))
		return
	}
	// Player names come from game servers; never let one ping the channel. Only the ids people chose are allowed.
	ids := d.Mentions.IDsFor(GameFrom(ctx))
	if len(ids) > 20 {
		ids = ids[:20]
	}
	allowed := map[string]any{"parse": []string{}}
	if len(ids) > 0 {
		allowed["users"] = ids
		var tags []string
		for _, id := range ids {
			tags = append(tags, "<@"+id+">")
		}
		message = strings.Join(tags, " ") + " " + message
	}
	body, _ := json.Marshal(map[string]any{
		"content":          truncate(message, discordLimit),
		"allowed_mentions": allowed,
	})
	deliver(ctx, "discord", httpClient(d.HTTPClient), d.retry, d.Status, func() (*http.Request, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.WebhookURL, bytes.NewReader(body))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		return req, nil
	})
}
