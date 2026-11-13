package dockerctl

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// maxExecOutput caps what an exec may print into memory: the commands CrowsNest runs print a line or a small file.
const maxExecOutput = 16 << 20

// Exec runs a command in a running container and returns its stdout (the Engine API's exec: create, then a hijacked
// start). Used by per-game StatusCheckers that need to inspect state inside the container (e.g. grep a log file for a
// readiness marker). A non-zero exit is an error carrying what the command wrote to stderr.
func (c *Client) Exec(ctx context.Context, name string, args ...string) (string, error) {
	return c.exec(ctx, name, nil, defaultShortTimeout, args)
}

// ExecTimeout is Exec with its own time limit, for long jobs such as a backup.
// The limit applies unless the client's Timeout override is set.
func (c *Client) ExecTimeout(ctx context.Context, name string, timeout time.Duration, args ...string) (string, error) {
	return c.exec(ctx, name, nil, timeout, args)
}

// ExecStdin is Exec with stdin as the command's standard input. Used to write a file into a container; the exec
// guard allowlists the exact command.
func (c *Client) ExecStdin(ctx context.Context, name string, stdin io.Reader, timeout time.Duration, args ...string) (string, error) {
	return c.exec(ctx, name, stdin, timeout, args)
}

func (c *Client) exec(ctx context.Context, name string, stdin io.Reader, timeout time.Duration, args []string) (string, error) {
	if c.Timeout > 0 {
		timeout = c.Timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := c.runExec(ctx, name, stdin, args)
	if err != nil && errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return "", fmt.Errorf("dockerctl: exec in %s: timed out after %s", name, timeout)
	}
	return out, err
}

func (c *Client) runExec(ctx context.Context, name string, stdin io.Reader, args []string) (string, error) {
	// The body is exactly what the exec guard accepts: no Env, User, Privileged or WorkingDir.
	create, err := json.Marshal(map[string]any{"AttachStdin": stdin != nil, "AttachStdout": true, "AttachStderr": true, "Tty": false, "Cmd": args})
	if err != nil {
		return "", err
	}
	resp, err := c.send(ctx, http.MethodPost, "/containers/"+url.PathEscape(name)+"/exec", nil, create)
	if err != nil {
		return "", err
	}
	var made struct {
		ID string `json:"Id"`
	}
	err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&made)
	_ = resp.Body.Close()
	if err != nil || made.ID == "" {
		return "", fmt.Errorf("dockerctl: exec in %s: the engine gave no exec id", name)
	}

	stdout, stderr, err := c.startExec(ctx, made.ID, stdin)
	if err != nil {
		return "", fmt.Errorf("dockerctl: exec in %s: %w", name, err)
	}
	code, err := c.execExit(ctx, made.ID)
	if err != nil {
		return "", err
	}
	if code != 0 {
		return "", fmt.Errorf("dockerctl: exec in %s: exit status %d: %s", name, code, strings.TrimSpace(stderr))
	}
	return stdout, nil
}

// startExec starts the exec over a raw connection, because it hijacks it: the answer is 101 and the rest of the
// connection carries the command's multiplexed output, and stdin goes the other way.
func (c *Client) startExec(ctx context.Context, id string, stdin io.Reader) (stdout, stderr string, err error) {
	base, socket, ok := c.target()
	if !ok {
		return "", "", errors.New("this Docker host scheme is not supported: use a unix socket or tcp:// (the guard)")
	}
	network, addr := "unix", socket
	if socket == "" {
		network, addr = "tcp", strings.TrimPrefix(base, "http://")
	}
	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr)
	if err != nil {
		return "", "", err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() }) // a deadline must end a blocked read
	defer stop()

	body := []byte(`{"Detach":false,"Tty":false}`)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base+"/exec/"+id+"/start", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "tcp")
	if err := req.Write(conn); err != nil {
		return "", "", err
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		return "", "", err
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		defer resp.Body.Close()
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", "", &apiError{Status: resp.StatusCode, Message: strings.TrimSpace(string(msg)), What: "POST /exec/start"}
	}

	if stdin != nil {
		go func() {
			_, _ = io.Copy(conn, stdin)
			if cw, ok := conn.(interface{ CloseWrite() error }); ok {
				_ = cw.CloseWrite() // the command sees end of input, as it does from `docker exec -i`
			}
		}()
	}
	var so, se bytes.Buffer
	if err := demuxSplit(br, &so, &se); err != nil {
		if ctx.Err() != nil {
			return "", "", ctx.Err()
		}
		return "", "", err
	}
	return so.String(), se.String(), nil
}

// demuxSplit reads the engine's stream framing: an 8-byte header (stream, 0, 0, 0, big-endian length) then that many
// bytes, until the stream ends.
func demuxSplit(r io.Reader, stdout, stderr *bytes.Buffer) error {
	var head [8]byte
	var total int64
	for {
		if _, err := io.ReadFull(r, head[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		n := int64(binary.BigEndian.Uint32(head[4:]))
		total += n
		if total > maxExecOutput {
			return errors.New("the command printed more than 16 MiB")
		}
		dst := stdout
		if head[0] == 2 {
			dst = stderr
		}
		if _, err := io.CopyN(dst, r, n); err != nil {
			return err
		}
	}
}

// execExit reads the exit code of a finished exec.
func (c *Client) execExit(ctx context.Context, id string) (int, error) {
	for i := 0; i < 50; i++ { // the engine can lag a moment behind the stream closing
		resp, err := c.get(ctx, "/exec/"+id+"/json", nil)
		if err != nil {
			return 0, err
		}
		var st struct {
			Running  bool
			ExitCode int
		}
		err = json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&st)
		_ = resp.Body.Close()
		if err != nil {
			return 0, err
		}
		if !st.Running {
			return st.ExitCode, nil
		}
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return 0, errors.New("dockerctl: the command did not report an exit status")
}
