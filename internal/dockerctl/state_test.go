package dockerctl

import (
	"context"
	"testing"
	"time"
)

func TestHTTP_State(t *testing.T) {
	c := newEngine(t, &fakeEngine{inspect: `{"RestartCount":4,"State":{"Running":true,"ExitCode":139,"OOMKilled":false,` +
		`"StartedAt":"2026-11-11T10:00:00Z","FinishedAt":"2026-11-11T09:59:00Z"}}`})
	st, err := c.State(context.Background(), "x")
	want := ContainerState{Running: true, ExitCode: 139, RestartCount: 4, FinishedAt: time.Date(2026, 11, 11, 9, 59, 0, 0, time.UTC)}
	if err != nil || st != want {
		t.Fatalf("State = %+v, %v; want %+v", st, err, want)
	}
	if _, err := c.State(context.Background(), "ghost"); err == nil {
		t.Fatal("State of a missing container should error")
	}
}
