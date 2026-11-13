// Package memadmit decides whether the host has the memory to start a game.
//
// Each game has a need: the largest memory it has been measured using, or,
// until it has run, the figure its module declares (or the instance's ram
// option). A start is admitted when the host's available memory, less a
// reserve and less what other starting games have yet to claim, covers it.
// A game with no known need, and a host whose memory cannot be read, are
// admitted: the active-game cap still applies, and a wrong guess here must
// never make a game impossible to start.
package memadmit

import (
	"encoding/json"
	"fmt"
	"github.com/fiddler110/crowsnest/internal/atomicfile"
	"os"
	"path/filepath"
	"sync"
)

// Error is a start refused for lack of memory. Handlers surface it as 409.
type Error struct {
	Game      string
	Need      uint64 // bytes the game needs
	Available uint64 // bytes usable now: host available less the reserve and pending starts
	Measured  bool   // Need is a measured peak, not a declared figure
}

func (e *Error) Error() string {
	return fmt.Sprintf("not enough memory to start %s: it needs about %s and the host has %s to spare", e.Game, Format(e.Need), Format(e.Available))
}

// Budget holds the measured peaks and answers admission questions.
type Budget struct {
	// Reserve is memory kept free for the host itself.
	Reserve uint64
	// Available returns the host's available memory in bytes, 0 if unknown.
	Available func() uint64
	// Declared returns a game's declared need in bytes, 0 if none.
	Declared func(id string) uint64

	file  string
	mu    sync.Mutex
	peaks map[string]uint64
}

// New loads the peaks saved in file, which may be missing; an empty file name
// keeps them in memory only.
func New(file string) *Budget {
	b := &Budget{file: file, peaks: map[string]uint64{}}
	if file != "" {
		if raw, err := os.ReadFile(file); err == nil { // #nosec G304 -- the operator's configured peaks file
			_ = json.Unmarshal(raw, &b.peaks)
		}
	}
	return b
}

// Need is the game's expected memory use and whether it is measured.
func (b *Budget) Need(id string) (bytes uint64, measured bool) {
	b.mu.Lock()
	p := b.peaks[id]
	b.mu.Unlock()
	if p > 0 {
		return p, true
	}
	if b.Declared != nil {
		return b.Declared(id), false
	}
	return 0, false
}

// Observe records a memory reading for a running game; the peak only rises.
// Readings are rounded up to 16 MiB so the file is not rewritten for noise.
func (b *Budget) Observe(id string, used uint64) {
	const step = 16 << 20
	used = (used + step - 1) / step * step
	b.mu.Lock()
	if used <= b.peaks[id] {
		b.mu.Unlock()
		return
	}
	b.peaks[id] = used
	raw, _ := json.Marshal(b.peaks)
	b.mu.Unlock()
	if b.file != "" {
		_ = atomicfile.Write(b.file, raw, 0o600) // a lost peak is measured again
	}
}

// Reset forgets a game's measured peak so its declared figure applies again,
// for after its settings change.
func (b *Budget) Reset(id string) {
	b.mu.Lock()
	delete(b.peaks, id)
	raw, _ := json.Marshal(b.peaks)
	b.mu.Unlock()
	if b.file != "" {
		_ = os.WriteFile(b.file, raw, 0o600)
	}
}

// Admit reports whether id may start. claimed is memory other starting games
// are expected to take and have not used yet; freed is memory a game that is
// being stopped for this start will give back. Both adjust the host's
// available memory, and both are estimates: a game still loading counts in
// full, which errs toward refusing.
func (b *Budget) Admit(id string, claimed, freed uint64) error {
	need, measured := b.Need(id)
	if need == 0 || b.Available == nil {
		return nil
	}
	avail := b.Available()
	if avail == 0 {
		return nil
	}
	avail += freed
	spare := uint64(0)
	if avail > b.Reserve+claimed {
		spare = avail - b.Reserve - claimed
	}
	if need > spare {
		return &Error{Game: id, Need: need, Available: spare, Measured: measured}
	}
	return nil
}

// Format renders bytes as MiB or GiB for messages.
func Format(n uint64) string {
	if n >= 1<<30 {
		return fmt.Sprintf("%.1f GiB", float64(n)/(1<<30))
	}
	return fmt.Sprintf("%d MiB", n>>20)
}

// DefaultFile is where peaks are kept next to the settings file.
func DefaultFile(settingsFile string) string {
	return filepath.Join(filepath.Dir(settingsFile), "memory-peaks.json")
}
