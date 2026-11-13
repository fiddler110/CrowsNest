// Package logging sets up the process's logs: leveled, as text or JSON. Code that still calls the standard
// library's log.Printf is routed through the same handler, with a level guessed from the message (a failure or
// refusal is a warning), so a level setting and the JSON format apply to everything.
package logging

import (
	"context"
	"fmt"
	"io"
	"log"
	"log/slog"
	"strings"
)

// Setup installs the default logger writing to w. level is debug, info, warn or error; format is "text" or "json".
func Setup(w io.Writer, level, format string) error {
	var lv slog.Level
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "", "info":
		lv = slog.LevelInfo
	case "debug":
		lv = slog.LevelDebug
	case "warn", "warning":
		lv = slog.LevelWarn
	case "error":
		lv = slog.LevelError
	default:
		return fmt.Errorf("log level %q: use debug, info, warn or error", level)
	}
	opts := &slog.HandlerOptions{Level: lv}
	var h slog.Handler
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		h = slog.NewTextHandler(w, opts)
	case "json":
		h = slog.NewJSONHandler(w, opts)
	default:
		return fmt.Errorf("log format %q: use text or json", format)
	}
	slog.SetDefault(slog.New(h))
	log.SetFlags(0)
	log.SetOutput(bridge{})
	return nil
}

// oneLine keeps a logged value from forging extra log lines.
var oneLine = strings.NewReplacer("\n", " ", "\r", " ")

// bridge takes lines from the standard log package.
type bridge struct{}

func (bridge) Write(p []byte) (int, error) {
	msg := oneLine.Replace(strings.TrimRight(string(p), "\n"))
	slog.Log(context.Background(), levelOf(msg), msg)
	return len(p), nil
}

var warnWords = []string{"failed", "error", "cannot", "can't", "unreachable", "refused", "denied", "not set", "unreadable", "skipped", "skipping", "disabled"}

func levelOf(msg string) slog.Level {
	l := strings.ToLower(msg)
	for _, w := range warnWords {
		if strings.Contains(l, w) {
			return slog.LevelWarn
		}
	}
	return slog.LevelInfo
}
