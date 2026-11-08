package dockerguard

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"regexp"
	"strconv"
	"sync"
	"time"
)

var contentLengthRe = regexp.MustCompile(`(?i)\r\ncontent-length:\s*(\d+)`)

// tunnel sends the (already checked) request on its own engine connection,
// with headers built here and Connection: close, then relays the answer. Client
// bytes go upstream only after the engine has switched an exec start to a raw
// stream (101); on any other stream, a client that sends more is disconnected,
// so nothing it sends after the checked request reaches the engine. The
// connection ends afterwards either way.
func (g *Guard) tunnel(c net.Conn, br *bufio.Reader, req *request, kind string) {
	defer c.Close()
	up, err := g.dial()
	if err != nil {
		g.reply(c, 502, "application/json", jsonMessage("docker socket: "+oneLine(err.Error())), false, true)
		return
	}
	defer up.Close()

	var head bytes.Buffer
	head.WriteString(req.method + " " + req.target() + " HTTP/1.1\r\nHost: docker\r\n")
	for _, k := range []string{"X-Registry-Auth", "User-Agent"} { // readRequest refused any header holding a line break
		if v := req.header.Get(k); v != "" {
			head.WriteString(k + ": " + v + "\r\n")
		}
	}
	if len(req.body) > 0 {
		head.WriteString("Content-Type: application/json\r\nContent-Length: " + strconv.Itoa(len(req.body)) + "\r\n")
	}
	if kind == "hijack" {
		head.WriteString("Upgrade: tcp\r\n") // the engine hijacks exec start either way; with this it answers 101
	}
	head.WriteString("Connection: close\r\n\r\n") // so a non-hijacked answer (an error, a detached exec) ends the connection
	head.Write(req.body)
	_ = up.SetWriteDeadline(time.Now().Add(30 * time.Second))
	if _, err := up.Write(head.Bytes()); err != nil {
		return
	}
	_ = up.SetWriteDeadline(time.Time{})

	// The engine's response head decides whether the client may talk.
	var resp []byte
	buf := make([]byte, 65536)
	for !bytes.Contains(resp, []byte("\r\n\r\n")) {
		_ = up.SetReadDeadline(time.Now().Add(g.streamIdle))
		n, err := up.Read(buf)
		resp = append(resp, buf[:n]...)
		if len(resp) > maxHead || (err != nil && !bytes.Contains(resp, []byte("\r\n\r\n"))) {
			return
		}
	}
	_ = c.SetWriteDeadline(time.Now().Add(g.streamIdle))
	if _, err := c.Write(resp); err != nil {
		return
	}
	_ = c.SetWriteDeadline(time.Time{}) // from here the idle timer below decides
	headEnd := bytes.Index(resp, []byte("\r\n\r\n")) + 4
	statusLine, _, _ := bytes.Cut(resp[:headEnd], []byte("\r\n"))
	fields := bytes.Split(statusLine, []byte(" "))
	upgraded := kind == "hijack" && len(fields) > 1 && string(fields[1]) == "101"

	if kind == "hijack" && !upgraded { // an error or a detached start: a plain answer, then nothing more
		left := -1
		if m := contentLengthRe.FindSubmatch(resp[:headEnd]); m != nil {
			n, _ := strconv.Atoi(string(m[1]))
			left = n - (len(resp) - headEnd)
		}
		for left != 0 {
			_ = up.SetReadDeadline(time.Now().Add(g.streamIdle))
			n, err := up.Read(buf)
			if n > 0 {
				if _, werr := c.Write(buf[:n]); werr != nil {
					return
				}
				if left > 0 {
					left -= n
				}
			}
			if err != nil {
				break
			}
		}
		lingerClose(c)
		return
	}
	_ = up.SetReadDeadline(time.Time{})

	// Two-way relay: a quiet stream is closed after streamIdle without traffic
	// in either direction.
	var once sync.Once
	closeBoth := func() { once.Do(func() { _ = c.Close(); _ = up.Close() }) }
	idle := time.AfterFunc(g.streamIdle, closeBoth)
	defer idle.Stop()
	defer closeBoth()
	touch := func() { idle.Reset(g.streamIdle) }

	go func() { // client -> engine; br first, it may already hold client bytes
		cbuf := make([]byte, 65536)
		for {
			n, err := br.Read(cbuf)
			if n > 0 {
				if !upgraded { // bytes after a non-hijacked request: never forwarded, the stream ends
					g.logf("DENY %s %s: client sent data on a stream", req.method, req.rawPath)
					closeBoth()
					return
				}
				touch()
				if _, werr := up.Write(cbuf[:n]); werr != nil {
					closeBoth()
					return
				}
			}
			if err != nil {
				if upgraded && err == io.EOF { // the client is done sending (stdin closed): pass that on, keep reading
					if cw, ok := up.(interface{ CloseWrite() error }); ok {
						_ = cw.CloseWrite()
					}
					return
				}
				closeBoth() // the client went away
				return
			}
		}
	}()

	for { // engine -> client
		n, err := up.Read(buf)
		if n > 0 {
			touch()
			if _, werr := c.Write(buf[:n]); werr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}
