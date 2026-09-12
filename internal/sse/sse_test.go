package sse

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// noFlush wraps an http.ResponseWriter without promoting a Flush method,
// even if the underlying value (e.g. httptest.ResponseRecorder) has one —
// embedding the interface type, not the concrete type, hides it.
type noFlush struct {
	http.ResponseWriter
}

func TestNewWriter_NotFlusher(t *testing.T) {
	rec := httptest.NewRecorder()
	w := noFlush{rec}

	sw, ok := NewWriter(w)
	if ok {
		t.Fatal("NewWriter() ok = true, want false for a non-Flusher ResponseWriter")
	}
	if sw != nil {
		t.Fatalf("NewWriter() = %v, want nil", sw)
	}
}

func TestNewWriter_SetsHeadersAndStatus(t *testing.T) {
	rec := httptest.NewRecorder()

	sw, ok := NewWriter(rec)
	if !ok {
		t.Fatal("NewWriter() ok = false, want true for httptest.ResponseRecorder")
	}
	if sw == nil {
		t.Fatal("NewWriter() sw = nil, want non-nil")
	}

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusOK)
	}
	h := rec.Header()
	want := map[string]string{
		"Content-Type":      "text/event-stream",
		"Cache-Control":     "no-cache",
		"X-Accel-Buffering": "no",
		"Connection":        "keep-alive",
	}
	for k, v := range want {
		if got := h.Get(k); got != v {
			t.Errorf("header %q = %q, want %q", k, got, v)
		}
	}
}

func TestWriteEvent_Named(t *testing.T) {
	rec := httptest.NewRecorder()
	sw, ok := NewWriter(rec)
	if !ok {
		t.Fatal("NewWriter() ok = false")
	}
	rec.Body.Reset()

	if err := sw.WriteEvent("progress", "50"); err != nil {
		t.Fatalf("WriteEvent() error = %v", err)
	}

	want := "event: progress\ndata: 50\n\n"
	if got := rec.Body.String(); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestWriteEvent_UnnamedHasNoEventLine(t *testing.T) {
	rec := httptest.NewRecorder()
	sw, ok := NewWriter(rec)
	if !ok {
		t.Fatal("NewWriter() ok = false")
	}
	rec.Body.Reset()

	if err := sw.WriteEvent("", "hello"); err != nil {
		t.Fatalf("WriteEvent() error = %v", err)
	}

	want := "data: hello\n\n"
	if got := rec.Body.String(); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestWriteEvent_MultiLineData(t *testing.T) {
	rec := httptest.NewRecorder()
	sw, ok := NewWriter(rec)
	if !ok {
		t.Fatal("NewWriter() ok = false")
	}
	rec.Body.Reset()

	if err := sw.WriteEvent("log", "line1\nline2\nline3"); err != nil {
		t.Fatalf("WriteEvent() error = %v", err)
	}

	want := "event: log\ndata: line1\ndata: line2\ndata: line3\n\n"
	if got := rec.Body.String(); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}

func TestWriteComment(t *testing.T) {
	rec := httptest.NewRecorder()
	sw, ok := NewWriter(rec)
	if !ok {
		t.Fatal("NewWriter() ok = false")
	}
	rec.Body.Reset()

	if err := sw.WriteComment("keepalive"); err != nil {
		t.Fatalf("WriteComment() error = %v", err)
	}

	want := ": keepalive\n\n"
	if got := rec.Body.String(); got != want {
		t.Fatalf("body = %q, want %q", got, want)
	}
}
