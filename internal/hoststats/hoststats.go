// Package hoststats reads the host's memory, load and disk space, so the
// dashboard can warn before a multi-GB image pull or a backup fills the disk.
// Linux only, like the rest of the runtime. Inside a container /proc/meminfo
// and /proc/loadavg describe the host; disks are whatever filesystems are
// mounted at the configured paths.
package hoststats

import (
	"bufio"
	"io"
	"os"
	"strconv"
	"strings"
	"syscall"
)

// Disk is the space on the filesystem backing Path.
type Disk struct {
	Path  string `json:"path"`
	Total uint64 `json:"total"`
	Free  uint64 `json:"free"` // available to unprivileged writers
}

// Snapshot is one reading. A field that couldn't be read is left zero.
type Snapshot struct {
	MemTotal     uint64  `json:"mem_total"`
	MemAvailable uint64  `json:"mem_available"`
	Load1        float64 `json:"load1"`
	Disks        []Disk  `json:"disks"`
}

// Read samples the host. Paths that don't exist are skipped, and several
// paths on one filesystem are reported once (the first listed).
func Read(paths []string) Snapshot {
	var s Snapshot
	if f, err := os.Open("/proc/meminfo"); err == nil {
		s.MemTotal, s.MemAvailable = parseMeminfo(f)
		f.Close()
	}
	if b, err := os.ReadFile("/proc/loadavg"); err == nil {
		s.Load1 = parseLoad(string(b))
	}
	seen := map[[2]int32]bool{}
	for _, p := range paths {
		var st syscall.Statfs_t
		if err := syscall.Statfs(p, &st); err != nil {
			continue
		}
		id := [2]int32{st.Fsid.X__val[0], st.Fsid.X__val[1]}
		if seen[id] {
			continue
		}
		seen[id] = true
		s.Disks = append(s.Disks, Disk{
			Path:  p,
			Total: st.Blocks * uint64(st.Bsize),
			Free:  st.Bavail * uint64(st.Bsize),
		})
	}
	return s
}

// parseMeminfo returns MemTotal and MemAvailable in bytes.
func parseMeminfo(r io.Reader) (total, available uint64) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		name, rest, ok := strings.Cut(sc.Text(), ":")
		if !ok {
			continue
		}
		fields := strings.Fields(rest)
		if len(fields) == 0 {
			continue
		}
		kb, err := strconv.ParseUint(fields[0], 10, 64)
		if err != nil {
			continue
		}
		switch name {
		case "MemTotal":
			total = kb * 1024
		case "MemAvailable":
			available = kb * 1024
		}
	}
	return total, available
}

func parseLoad(s string) float64 {
	f := strings.Fields(s)
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}
