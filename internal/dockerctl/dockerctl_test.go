package dockerctl

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// newFakeBin writes script as an executable called name and returns its path.
func newFakeBin(t *testing.T, name, script string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
	return path
}

func TestGPUStats_CachesReading(t *testing.T) {
	count := filepath.Join(t.TempDir(), "count")
	bin := newFakeBin(t, "nvidia-smi", "#!/bin/sh\necho x >> "+count+"\necho '45, 2048, 8192'\n")
	c := &Client{NvidiaSmiBin: bin}
	for i := 0; i < 3; i++ {
		if _, ok := c.GPUStats(context.Background()); !ok {
			t.Fatal("GPUStats() ok = false, want true")
		}
	}
	b, _ := os.ReadFile(count)
	if n := strings.Count(string(b), "x"); n != 1 {
		t.Fatalf("nvidia-smi ran %d times, want 1 (cached)", n)
	}
}

func TestGPUStats_MissingBinaryStopsTrying(t *testing.T) {
	c := &Client{NvidiaSmiBin: filepath.Join(t.TempDir(), "nope")}
	if _, ok := c.GPUStats(context.Background()); ok {
		t.Fatal("ok = true, want false")
	}
	if !c.gpuMissing {
		t.Fatal("gpuMissing = false, want true after a missing binary")
	}
}

func TestGPUStats_Success(t *testing.T) {
	c := &Client{NvidiaSmiBin: newFakeBin(t, "nvidia-smi", "#!/bin/sh\nprintf '45, 2048, 8192\\n'\n")}
	g, ok := c.GPUStats(context.Background())
	if !ok {
		t.Fatal("GPUStats() ok = false, want true")
	}
	want := GPUStats{UtilPercent: "45", MemUsedMiB: "2048", MemTotalMiB: "8192"}
	if g != want {
		t.Fatalf("GPUStats() = %+v, want %+v", g, want)
	}
}

func TestGPUStats_Unavailable(t *testing.T) {
	c := &Client{NvidiaSmiBin: filepath.Join(t.TempDir(), "does-not-exist")}
	g, ok := c.GPUStats(context.Background())
	if ok {
		t.Fatalf("GPUStats() ok = true, want false when nvidia-smi is unavailable; got %+v", g)
	}
}

func TestGPUStats_MalformedOutput(t *testing.T) {
	c := &Client{NvidiaSmiBin: newFakeBin(t, "nvidia-smi", "#!/bin/sh\nprintf 'not what we expected\\n'\n")}
	g, ok := c.GPUStats(context.Background())
	if ok {
		t.Fatalf("GPUStats() ok = true, want false for malformed output; got %+v", g)
	}
}
