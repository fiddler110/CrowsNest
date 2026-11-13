package notify

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

var fast = retry{Attempts: 3, Base: time.Millisecond, MaxWait: 20 * time.Millisecond}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("short text changed: %q", got)
	}
	got := truncate(strings.Repeat("é", 3000), 2000)
	if n := len([]rune(got)); n != 2000 || !strings.HasSuffix(got, "…") {
		t.Errorf("got %d runes, suffix ok=%v", n, strings.HasSuffix(got, "…"))
	}
}

func TestWebhook_RetriesServerErrorsThenSucceeds(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if n.Add(1) < 3 {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	st := &Status{}
	(&Webhook{URL: srv.URL, Status: st, retry: fast}).Notify(context.Background(), "hi")
	if n.Load() != 3 || !st.Healthy() {
		t.Fatalf("attempts=%d healthy=%v, want 3 and healthy", n.Load(), st.Healthy())
	}
}

func TestWebhook_429HonoursRetryAfterAndGivesUp(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.Header().Set("Retry-After", "0.001")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	st := &Status{}
	(&Webhook{URL: srv.URL, Status: st, retry: fast}).Notify(context.Background(), "hi")
	f := st.Failing()
	if n.Load() != 3 || len(f) != 1 || f[0].Channel != "webhook" || !strings.Contains(f[0].Error, "429") {
		t.Fatalf("attempts=%d failing=%+v", n.Load(), f)
	}
}

func TestWebhook_ClientErrorIsNotRetried(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n.Add(1)
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	st := &Status{}
	(&Webhook{URL: srv.URL, Status: st, retry: fast}).Notify(context.Background(), "hi")
	if n.Load() != 1 || st.Healthy() {
		t.Fatalf("attempts=%d healthy=%v, want 1 and failing", n.Load(), st.Healthy())
	}
}

func TestStatusRecoversAfterASuccess(t *testing.T) {
	var fail atomic.Bool
	fail.Store(true)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	st := &Status{}
	w := &Webhook{URL: srv.URL, Status: st, retry: fast}
	w.Notify(context.Background(), "a")
	if st.Healthy() {
		t.Fatal("want failing")
	}
	fail.Store(false)
	w.Notify(context.Background(), "b")
	if !st.Healthy() {
		t.Fatal("want healthy after a good send")
	}
}

func TestNtfy_SendsTextAndToken(t *testing.T) {
	var body, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 100)
		n, _ := r.Body.Read(b)
		body, auth = string(b[:n]), r.Header.Get("Authorization")
	}))
	defer srv.Close()
	(&Ntfy{URL: srv.URL, Token: "tk", retry: fast}).Notify(context.Background(), "palworld started")
	if body != "palworld started" || auth != "Bearer tk" {
		t.Fatalf("body=%q auth=%q", body, auth)
	}
}

func TestMultiReachesEveryChannel(t *testing.T) {
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.Add(1) }))
	defer srv.Close()
	Multi{&Ntfy{URL: srv.URL}, &Webhook{URL: srv.URL}, &Webhook{}}.Notify(context.Background(), "x")
	if n.Load() != 2 {
		t.Fatalf("got %d posts, want 2 (the unset webhook is inert)", n.Load())
	}
}

func TestDiscord_CutsLongMessages(t *testing.T) {
	var got string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var m map[string]any
		_ = jsonDecode(r, &m)
		got, _ = m["content"].(string)
	}))
	defer srv.Close()
	d := &Discord{WebhookURL: discordWebhookPrefix + "1/x", HTTPClient: &http.Client{Transport: rewriteHostTransport{target: srv.URL}}}
	d.Notify(context.Background(), strings.Repeat("a", 5000))
	if len([]rune(got)) != 2000 {
		t.Fatalf("content has %d characters, want 2000", len([]rune(got)))
	}
}

func jsonDecode(r *http.Request, v any) error { return json.NewDecoder(r.Body).Decode(v) }
