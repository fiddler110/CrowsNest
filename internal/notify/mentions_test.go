package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

func TestMentionsStore(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mentions.json")
	s, err := OpenMentions(path)
	if err != nil {
		t.Fatal(err)
	}
	known := func(g string) bool { return g == "valheim" || g == "palworld" }
	if err := s.Set("amy", "12345678901234567", []string{"valheim", "gone", "valheim"}, known); err != nil {
		t.Fatal(err)
	}
	if err := s.Set("bob", "not-a-number", []string{"valheim"}, known); err == nil {
		t.Error("a non-numeric id was accepted")
	}
	if got := s.IDsFor("valheim"); len(got) != 1 || got[0] != "12345678901234567" {
		t.Fatalf("ids = %v", got)
	}
	if got := s.IDsFor("palworld"); len(got) != 0 {
		t.Fatalf("palworld ids = %v", got)
	}
	again, err := OpenMentions(path)
	if err != nil || again.Get("amy").DiscordID == "" || len(again.Get("amy").Games) != 1 {
		t.Fatalf("reload = %+v, %v", again.Get("amy"), err)
	}
}

func TestDiscordMentionsOptedInUsers(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&body)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer srv.Close()
	m, _ := OpenMentions("")
	m.Set("amy", "12345678901234567", []string{"valheim"}, func(string) bool { return true })
	d := &Discord{WebhookURL: discordWebhookPrefix + "1/a", Mentions: m, HTTPClient: &http.Client{Transport: rewriteHostTransport{target: srv.URL}}}

	d.Notify(WithGame(context.Background(), "valheim"), "stopped")
	if c, _ := body["content"].(string); !strings.HasPrefix(c, "<@12345678901234567> ") {
		t.Fatalf("content = %q, want a mention", c)
	}
	am := body["allowed_mentions"].(map[string]any)
	if u, _ := am["users"].([]any); len(u) != 1 {
		t.Fatalf("allowed_mentions = %v", am)
	}

	body = nil
	d.Notify(WithGame(context.Background(), "palworld"), "stopped")
	if c, _ := body["content"].(string); c != "stopped" {
		t.Fatalf("other game content = %q, want no mention", c)
	}
}
