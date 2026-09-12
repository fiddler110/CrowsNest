package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestDiscord_Notify_EmptyURLIsNoop(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	d := &Discord{}
	d.Notify(context.Background(), "hello")
	if called {
		t.Fatal("Notify() with empty WebhookURL made an HTTP request, want no-op")
	}
}

func TestDiscord_Notify_NilReceiverIsNoop(t *testing.T) {
	var d *Discord
	d.Notify(context.Background(), "hello") // must not panic
}

func TestDiscord_Notify_RejectsNonDiscordURL(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	defer srv.Close()

	d := &Discord{WebhookURL: srv.URL}
	d.Notify(context.Background(), "hello")
	if called {
		t.Fatal("Notify() with a non-Discord URL made an HTTP request, want it rejected")
	}
}

func TestDiscord_Notify_PostsContent(t *testing.T) {
	var gotBody map[string]string
	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()

	// Notify only special-cases the real Discord prefix, so point the
	// client at the test server by overriding the scheme+host it actually
	// hits while keeping a URL that starts with the required prefix.
	d := &Discord{WebhookURL: discordWebhookPrefix + "123/abc"}
	d.HTTPClient = srv.Client()
	// Redirect via a custom transport so the request lands on srv despite
	// the discord.com URL.
	d.HTTPClient.Transport = rewriteHostTransport{target: srv.URL}

	d.Notify(context.Background(), "🌙 test message")

	if gotPath != "/api/webhooks/123/abc" {
		t.Fatalf("path = %q, want /api/webhooks/123/abc", gotPath)
	}
	if gotBody["content"] != "🌙 test message" {
		t.Fatalf("content = %q, want the message", gotBody["content"])
	}
}

// rewriteHostTransport rewrites every request to target's host, preserving
// path/query, so tests can point a Discord-prefixed URL at an httptest
// server.
type rewriteHostTransport struct{ target string }

func (t rewriteHostTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	targetURL := t.target + req.URL.Path
	newReq, err := http.NewRequestWithContext(req.Context(), req.Method, targetURL, req.Body)
	if err != nil {
		return nil, err
	}
	newReq.Header = req.Header
	return http.DefaultTransport.RoundTrip(newReq)
}
