package games

// PassthroughFormatter is the default LogLineFormatter: it emits every raw
// log line verbatim as an unnamed SSE event (so EventSource's onmessage
// fires), matching the original Python CrowsNest's log streaming, which
// never classified lines into warn/error/verbose.
type PassthroughFormatter struct{}

func (PassthroughFormatter) Format(raw string) (event string, text string) {
	return "", raw
}
