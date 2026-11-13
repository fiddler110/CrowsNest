// Package audit keeps the tamper-evident record of security-relevant actions: sign-ins and refusals, user changes,
// starts, stops and switches, settings and console use. It is a JSON-lines file of its own, apart from the
// activity log (which is pruned and shown on the dashboard). Each entry carries the hash of the one before it, so
// editing, deleting or reordering an entry in the middle of the file breaks the chain from that point on. Cutting
// entries off the end is not detectable from the file alone; note the last hash `crowsnest audit verify` prints to
// catch that.
package audit

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Genesis is the "previous hash" of the first entry.
const Genesis = "0000000000000000000000000000000000000000000000000000000000000000"

// Entry is one line of the file.
type Entry struct {
	N    uint64    `json:"n"`
	Time time.Time `json:"t"`
	Msg  string    `json:"msg"`
	Prev string    `json:"prev"`
	Hash string    `json:"hash"`
}

func (e Entry) sum() string {
	h := sha256.Sum256([]byte(fmt.Sprintf("%d\n%s\n%s\n%s", e.N, e.Time.UTC().Format(time.RFC3339Nano), e.Msg, e.Prev)))
	return hex.EncodeToString(h[:])
}

// Log appends entries. The zero value and a nil *Log discard them (the message is still logged).
type Log struct {
	mu   sync.Mutex
	f    *os.File
	n    uint64
	last string
	path string
}

// Open opens path for appending and carries on from the chain already in it. It refuses a file whose chain is
// broken, so a damaged record is looked at rather than quietly extended.
func Open(path string) (*Log, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	n, last, err := Verify(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("audit: %s: %w (move the file aside to start a new record)", path, err)
	}
	if last == "" {
		last = Genesis
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600) // #nosec G304 -- operator-configured path
	if err != nil {
		return nil, fmt.Errorf("audit: %w", err)
	}
	return &Log{f: f, n: n, last: last, path: path}, nil
}

// Close closes the file.
func (l *Log) Close() error {
	if l == nil || l.f == nil {
		return nil
	}
	return l.f.Close()
}

// Path is the file's location ("" when there is none).
func (l *Log) Path() string {
	if l == nil {
		return ""
	}
	return l.path
}

// Record appends msg.
func (l *Log) Record(msg string) {
	slog.Info(strings.NewReplacer("\n", " ", "\r", " ").Replace(msg), "audit", true)
	if l == nil || l.f == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	e := Entry{N: l.n + 1, Time: time.Now().UTC(), Msg: msg, Prev: l.last}
	e.Hash = e.sum()
	b, _ := json.Marshal(e)
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		slog.Error("audit: could not write the audit file", "err", err)
		return
	}
	l.n, l.last = e.N, e.Hash
}

// Default is where Printf writes. main sets it; until then entries are only logged.
var Default *Log

// Printf records a formatted entry in Default.
func Printf(format string, args ...any) { Default.Record(fmt.Sprintf(format, args...)) }

// Verify walks the file and returns how many entries it holds and the last hash. A missing file is
// os.ErrNotExist. The error names the first line that does not fit: a wrong hash (an entry was edited), a wrong
// link (one was removed, added or moved) or text that is not an entry.
func Verify(path string) (n uint64, last string, err error) {
	f, err := os.Open(path) // #nosec G304 -- operator-configured path
	if err != nil {
		return 0, "", err
	}
	defer f.Close()
	return verify(f)
}

func verify(r io.Reader) (n uint64, last string, err error) {
	prev := Genesis
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	line := 0
	for sc.Scan() {
		line++
		var e Entry
		if json.Unmarshal(sc.Bytes(), &e) != nil {
			return n, prev, fmt.Errorf("line %d is not an audit entry", line)
		}
		switch {
		case e.Prev != prev || e.N != n+1:
			return n, prev, fmt.Errorf("line %d does not follow the one before it (an entry was removed, added or moved)", line)
		case e.Hash != e.sum():
			return n, prev, fmt.Errorf("line %d was changed after it was written", line)
		}
		n, prev = e.N, e.Hash
	}
	if err := sc.Err(); err != nil {
		return n, prev, err
	}
	if n == 0 {
		return 0, "", nil
	}
	return n, prev, nil
}
