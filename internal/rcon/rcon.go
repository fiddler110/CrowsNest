// Package rcon is a minimal client for the Source RCON protocol, which is
// what Palworld (and many other dedicated servers) speak on their RCON port.
// One connection per command: these are occasional admin actions, and it
// keeps a wedged server from leaving a half-open session behind.
package rcon

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

const (
	typeResponse = 0
	typeExec     = 2
	typeAuth     = 3

	// maxPacket bounds what we will allocate for a single reply packet.
	maxPacket = 64 << 10
)

// ErrAuth means the server rejected the password.
var ErrAuth = errors.New("rcon: authentication failed")

// Exec connects to addr (host:port), authenticates, runs command and returns
// the reply text. timeout bounds the whole exchange.
func Exec(ctx context.Context, addr, password, command string, timeout time.Duration) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	if dl, ok := ctx.Deadline(); ok {
		conn.SetDeadline(dl)
	}

	if err := write(conn, 1, typeAuth, password); err != nil {
		return "", err
	}
	// Servers send an empty response packet and then the auth result; some
	// send only the result. Read until the auth-response (type 2) arrives.
	for {
		id, typ, _, err := read(conn)
		if err != nil {
			return "", err
		}
		if typ == typeExec { // SERVERDATA_AUTH_RESPONSE shares the value 2
			if id == -1 {
				return "", ErrAuth
			}
			break
		}
	}

	// A follow-up empty command marks the end of a multi-packet reply: the
	// server answers requests in order, so when its answer to the marker
	// arrives, everything before it was ours.
	if err := write(conn, 2, typeExec, command); err != nil {
		return "", err
	}
	if err := write(conn, 3, typeResponse, ""); err != nil {
		return "", err
	}
	var out strings.Builder
	for {
		id, _, body, err := read(conn)
		if err != nil {
			// Palworld sometimes answers the command and never the marker.
			if out.Len() > 0 && isTimeout(err) {
				break
			}
			return out.String(), err
		}
		if id == 3 {
			break
		}
		if id == 2 {
			out.WriteString(body)
		}
	}
	return strings.TrimRight(out.String(), "\x00\r\n "), nil
}

func isTimeout(err error) bool {
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

func write(w io.Writer, id int32, typ int32, body string) error {
	buf := make([]byte, 4+4+4+len(body)+2)
	binary.LittleEndian.PutUint32(buf[0:], uint32(4+4+len(body)+2))
	binary.LittleEndian.PutUint32(buf[4:], uint32(id))
	binary.LittleEndian.PutUint32(buf[8:], uint32(typ))
	copy(buf[12:], body)
	_, err := w.Write(buf)
	return err
}

func read(r io.Reader) (id int32, typ int32, body string, err error) {
	var hdr [4]byte
	if _, err = io.ReadFull(r, hdr[:]); err != nil {
		return
	}
	n := binary.LittleEndian.Uint32(hdr[:])
	if n < 10 || n > maxPacket {
		return 0, 0, "", fmt.Errorf("rcon: bad packet length %d", n)
	}
	buf := make([]byte, n)
	if _, err = io.ReadFull(r, buf); err != nil {
		return
	}
	id = int32(binary.LittleEndian.Uint32(buf[0:]))
	typ = int32(binary.LittleEndian.Uint32(buf[4:]))
	body = strings.TrimRight(string(buf[8:]), "\x00")
	return
}
