package backup

import (
	"encoding/json"
	"fmt"
	"os"
	"time"
)

// The offsite sidecar (quickstart/offsite) writes a small status file after every copy. The panel only reads it:
// it holds no credentials and does not run the copy, so all it can say is what the sidecar last reported, and that
// the report has stopped coming.

// Offsite states.
const (
	OffsiteOK      = "ok"
	OffsiteFailed  = "failed"  // the last copy reported an error
	OffsiteStale   = "stale"   // no report for far longer than its interval: the sidecar is down or stuck
	OffsiteMissing = "missing" // the status file is not there (yet)
)

// OffsiteStatus is what the dashboard shows about the offsite copy.
type OffsiteStatus struct {
	Configured bool      `json:"configured"`
	State      string    `json:"state,omitempty"`
	Remote     string    `json:"remote,omitempty"`
	At         time.Time `json:"at,omitempty"`      // the last attempt
	LastOK     time.Time `json:"last_ok,omitempty"` // the last attempt that succeeded
	Interval   int       `json:"interval_seconds,omitempty"`
	Message    string    `json:"message,omitempty"`
}

// Healthy is true when nothing is configured or the last copy went well.
func (s OffsiteStatus) Healthy() bool { return !s.Configured || s.State == OffsiteOK }

type offsiteFile struct {
	OK       bool      `json:"ok"`
	At       time.Time `json:"at"`
	LastOK   time.Time `json:"last_ok"`
	Interval int       `json:"interval_seconds"`
	Remote   string    `json:"remote"`
	Error    string    `json:"error"`
}

// maxOffsiteFile caps what is read: a status file is a few hundred bytes.
const maxOffsiteFile = 16 << 10

// ReadOffsite reads the sidecar's status file at path as of now. An empty path means the feature is off.
func ReadOffsite(path string, now time.Time) OffsiteStatus {
	if path == "" {
		return OffsiteStatus{}
	}
	st := OffsiteStatus{Configured: true}
	f, err := os.Open(path) // #nosec G304 -- path is the operator's platform.offsite_status_file
	if err != nil {
		st.State, st.Message = OffsiteMissing, "the offsite sidecar has not reported yet (no status file)"
		return st
	}
	defer f.Close()
	var in offsiteFile
	dec := json.NewDecoder(&limited{f: f, left: maxOffsiteFile})
	if err := dec.Decode(&in); err != nil {
		st.State, st.Message = OffsiteMissing, "the offsite status file is unreadable: "+err.Error()
		return st
	}
	st.At, st.LastOK, st.Interval, st.Remote = in.At, in.LastOK, in.Interval, in.Remote
	// Stale: no report for two intervals and ten minutes (a copy itself can take a while). Checked first, since a
	// dead sidecar leaves its last words, good or bad, in the file forever.
	if in.Interval > 0 && now.Sub(in.At) > time.Duration(2*in.Interval)*time.Second+10*time.Minute {
		st.State = OffsiteStale
		st.Message = fmt.Sprintf("no report from the offsite sidecar since %s", in.At.Local().Format("2006-01-02 15:04"))
		return st
	}
	if !in.OK {
		st.State = OffsiteFailed
		st.Message = in.Error
		if st.Message == "" {
			st.Message = "the last offsite copy failed"
		}
		return st
	}
	st.State = OffsiteOK
	return st
}

type limited struct {
	f    *os.File
	left int
}

func (l *limited) Read(p []byte) (int, error) {
	if l.left <= 0 {
		return 0, fmt.Errorf("status file is larger than %d bytes", maxOffsiteFile)
	}
	if len(p) > l.left {
		p = p[:l.left]
	}
	n, err := l.f.Read(p)
	l.left -= n
	return n, err
}
