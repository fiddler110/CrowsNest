package main

import (
	"context"
	"log"
	"path/filepath"
	"time"

	"github.com/fiddler110/crowsnest/internal/config"
	"github.com/fiddler110/crowsnest/internal/dockerctl"
	"github.com/fiddler110/crowsnest/internal/games"
	"github.com/fiddler110/crowsnest/internal/hoststats"
	"github.com/fiddler110/crowsnest/internal/memadmit"
)

const memorySampleEvery = 30 * time.Second

// newMemoryBudget builds the start-admission budget: declared figures from the
// registry until a game has run, then its measured peak. It returns nil when
// the operator turned the check off.
func newMemoryBudget(cfg *config.Config, registry *games.Registry) *memadmit.Budget {
	if cfg.Server.MemoryReserveMB < 0 {
		log.Printf("memory admission: off (server.memory_reserve_mb < 0)")
		return nil
	}
	reserve := cfg.Server.MemoryReserveMB
	if reserve == 0 {
		reserve = 1024
	}
	b := memadmit.New(filepath.Join(filepath.Dir(cfg.Server.SettingsFile), "memory-peaks.json"))
	b.Reserve = uint64(reserve) << 20
	b.Available = func() uint64 { return hoststats.Read(nil).MemAvailable }
	b.Declared = func(id string) uint64 {
		if d, ok := registry.Get(id); ok {
			return d.RAMEstimate
		}
		return 0
	}
	log.Printf("memory admission: on, %d MiB kept free for the host", reserve)
	return b
}

// sampleMemory records each running game's memory use so its peak replaces the
// declared figure. A container that is not running just fails its read.
func sampleMemory(ctx context.Context, b *memadmit.Budget, docker *dockerctl.Client, registry *games.Registry) {
	t := time.NewTicker(memorySampleEvery)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		for _, d := range registry.All() {
			if s, err := docker.Stats(ctx, d.ContainerName); err == nil && s.MemUsedBytes > 0 {
				b.Observe(d.ID, s.MemUsedBytes)
			}
		}
	}
}
