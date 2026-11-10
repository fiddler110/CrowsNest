package memadmit

import (
	"errors"
	"path/filepath"
	"testing"
)

const gib = 1 << 30

func budget(avail uint64) *Budget {
	b := New("")
	b.Reserve = 1 * gib
	b.Available = func() uint64 { return avail }
	b.Declared = func(id string) uint64 { return map[string]uint64{"big": 8 * gib, "small": 1 * gib}[id] }
	return b
}

func TestAdmitUsesReserve(t *testing.T) {
	b := budget(9 * gib)
	if err := b.Admit("big", 0, 0); err != nil {
		t.Fatalf("8 GiB with 9 free and 1 reserved should fit: %v", err)
	}
	var e *Error
	if err := budget(8*gib).Admit("big", 0, 0); !errors.As(err, &e) || e.Available != 7*gib {
		t.Fatalf("got %v, want a refusal with 7 GiB spare", err)
	}
}

func TestAdmitClaimedAndFreed(t *testing.T) {
	b := budget(9 * gib)
	if err := b.Admit("big", 2*gib, 0); err == nil {
		t.Fatal("memory claimed by a starting game must count")
	}
	if err := budget(5*gib).Admit("big", 0, 4*gib); err != nil {
		t.Fatalf("memory freed by the stopping game must count: %v", err)
	}
}

func TestAdmitUnknownsPass(t *testing.T) {
	if err := budget(0).Admit("big", 0, 0); err != nil {
		t.Fatalf("unreadable host memory: %v", err)
	}
	if err := budget(1).Admit("undeclared", 0, 0); err != nil {
		t.Fatalf("no known need: %v", err)
	}
}

func TestMeasuredPeakReplacesDeclared(t *testing.T) {
	b := budget(5 * gib)
	if need, measured := b.Need("big"); need != 8*gib || measured {
		t.Fatalf("Need = %d,%v before a run", need, measured)
	}
	b.Observe("big", 3*gib)
	b.Observe("big", 2*gib) // the peak only rises
	if need, measured := b.Need("big"); need != 3*gib || !measured {
		t.Fatalf("Need = %d,%v after a run, want 3 GiB measured", need, measured)
	}
	if err := b.Admit("big", 0, 0); err != nil {
		t.Fatalf("3 GiB measured fits in 5 free: %v", err)
	}
	b.Reset("big")
	if need, _ := b.Need("big"); need != 8*gib {
		t.Fatalf("Reset should bring the declared figure back, got %d", need)
	}
}

func TestPeaksPersist(t *testing.T) {
	f := filepath.Join(t.TempDir(), "peaks.json")
	New(f).Observe("g", 5*gib)
	if need, measured := New(f).Need("g"); need != 5*gib || !measured {
		t.Fatalf("reloaded Need = %d,%v", need, measured)
	}
}
