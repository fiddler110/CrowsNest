package hoststats

import (
	"strings"
	"testing"
)

func TestParseMeminfo(t *testing.T) {
	total, avail := parseMeminfo(strings.NewReader("MemTotal:       16384000 kB\nMemFree:  100 kB\nMemAvailable:    8192000 kB\nJunk\n"))
	if total != 16384000*1024 || avail != 8192000*1024 {
		t.Fatalf("got %d / %d", total, avail)
	}
}

func TestParseLoad(t *testing.T) {
	if got := parseLoad("1.25 0.80 0.50 1/300 1234\n"); got != 1.25 {
		t.Fatalf("got %v", got)
	}
	if parseLoad("") != 0 {
		t.Fatal("empty input should be 0")
	}
}

func TestReadDedupesAndSkipsMissing(t *testing.T) {
	dir := t.TempDir()
	s := Read([]string{dir, dir + "/", "/definitely/not/here"})
	if len(s.Disks) != 1 || s.Disks[0].Total == 0 || s.Disks[0].Free > s.Disks[0].Total {
		t.Fatalf("disks = %+v", s.Disks)
	}
	if s.MemTotal == 0 {
		t.Skip("no /proc/meminfo here")
	}
}
