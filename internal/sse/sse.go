// Package sse is a tiny Server-Sent-Events writer shared by every SSE
// endpoint in internal/web (log streaming and startup-progress streaming).
package sse

import (
	"fmt"
	"net/http"
	"strings"
)

// Writer sends Server-Sent Events over an http.ResponseWriter, flushing
// after every write so events reach the client immediately rather than
// sitting in a buffer.
type Writer struct {
	w       http.ResponseWriter
	flusher http.Flusher
}

// NewWriter prepares w for an SSE stream: sets the standard SSE headers,
// writes the 200 status, and flushes. ok is false if w doesn't support
// flushing (http.Flusher), in which case streaming isn't possible and the
// caller should fall back to a plain error response.
func NewWriter(w http.ResponseWriter) (sw *Writer, ok bool) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return nil, false
	}
	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("X-Accel-Buffering", "no")
	h.Set("Connection", "keep-alive")
	w.WriteHeader(http.StatusOK)
	flusher.Flush()
	return &Writer{w: w, flusher: flusher}, true
}

// WriteEvent writes one SSE event. An empty event name omits the "event:"
// line, so the client's EventSource.onmessage fires (the SSE default) —
// used for plain log passthrough that isn't classified into a named type.
// data is split on "\n" into one "data:" line per line, per the SSE spec.
func (sw *Writer) WriteEvent(event, data string) error {
	var b strings.Builder
	if event != "" {
		fmt.Fprintf(&b, "event: %s\n", event)
	}
	for _, line := range strings.Split(data, "\n") {
		fmt.Fprintf(&b, "data: %s\n", line)
	}
	b.WriteString("\n")
	if _, err := sw.w.Write([]byte(b.String())); err != nil {
		return err
	}
	sw.flusher.Flush()
	return nil
}

// WriteComment writes an SSE comment line (ignored by EventSource, but
// keeps intermediary proxies and the client's connection from timing out
// during quiet periods).
func (sw *Writer) WriteComment(comment string) error {
	if _, err := fmt.Fprintf(sw.w, ": %s\n\n", comment); err != nil {
		return err
	}
	sw.flusher.Flush()
	return nil
}
