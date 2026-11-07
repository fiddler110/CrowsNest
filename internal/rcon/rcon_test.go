package rcon

import (
	"context"
	"net"
	"testing"
	"time"
)

// fakeServer speaks just enough RCON: password "pw", and replies to a command
// with two packets so multi-packet handling is exercised.
func fakeServer(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				for {
					id, typ, body, err := read(c)
					if err != nil {
						return
					}
					switch {
					case typ == typeAuth:
						write(c, id, typeResponse, "")
						if body == "pw" {
							write(c, id, typeExec, "")
						} else {
							write(c, -1, typeExec, "")
						}
					case typ == typeExec:
						write(c, id, typeResponse, "part one, ")
						write(c, id, typeResponse, "echo:"+body)
					default: // marker
						write(c, id, typeResponse, "")
					}
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestExec(t *testing.T) {
	addr := fakeServer(t)
	got, err := Exec(context.Background(), addr, "pw", "Info", 2*time.Second)
	if err != nil || got != "part one, echo:Info" {
		t.Fatalf("got %q, %v", got, err)
	}
}

func TestExecBadPassword(t *testing.T) {
	addr := fakeServer(t)
	if _, err := Exec(context.Background(), addr, "nope", "Info", 2*time.Second); err != ErrAuth {
		t.Fatalf("err = %v", err)
	}
}

func TestExecUnreachable(t *testing.T) {
	if _, err := Exec(context.Background(), "127.0.0.1:1", "pw", "x", time.Second); err == nil {
		t.Fatal("want error")
	}
}
