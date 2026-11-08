// Package memo is a tiny keyed TTL cache with request coalescing: however many
// callers ask for the same key at once (browser tabs polling the dashboard),
// the underlying work — a docker subprocess, an HTTP probe — runs once per
// TTL, and they all share its result.
package memo

import (
	"context"
	"sync"
	"time"
)

// detachedTimeout bounds one shared computation. It runs detached from any
// single caller's context so one client hanging up can't fail the others.
const detachedTimeout = 20 * time.Second

type flight[T any] struct {
	done chan struct{}
	val  T
}

type entry[T any] struct {
	val    T
	at     time.Time
	has    bool
	gen    uint64 // bumped by Forget; a flight from an older generation isn't stored
	flight *flight[T]
}

// Memo caches values of type T by string key. The zero value is ready to use.
type Memo[T any] struct {
	mu sync.Mutex
	m  map[string]*entry[T]

	// Now overrides time.Now (tests).
	Now func() time.Time
}

func (m *Memo[T]) now() time.Time {
	if m.Now != nil {
		return m.Now()
	}
	return time.Now()
}

// Do returns the cached value for key if it is younger than ttl, else runs
// fn (or joins the run already in flight) and caches the result. ttl <= 0
// disables caching entirely (fn runs directly, uncoalesced). The error is
// ctx's, when the caller gave up waiting.
func (m *Memo[T]) Do(ctx context.Context, key string, ttl time.Duration, fn func(context.Context) T) (T, error) {
	if ttl <= 0 {
		return fn(ctx), nil
	}
	m.mu.Lock()
	if m.m == nil {
		m.m = map[string]*entry[T]{}
	}
	e := m.m[key]
	if e == nil {
		e = &entry[T]{}
		m.m[key] = e
	}
	if e.has && m.now().Sub(e.at) < ttl {
		v := e.val
		m.mu.Unlock()
		return v, nil
	}
	f := e.flight
	if f == nil {
		f = &flight[T]{done: make(chan struct{})}
		e.flight = f
		gen := e.gen
		go func() {
			dctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), detachedTimeout)
			defer cancel()
			v := fn(dctx)
			m.mu.Lock()
			if e.gen == gen {
				e.val, e.at, e.has = v, m.now(), true
			}
			e.flight = nil
			m.mu.Unlock()
			f.val = v
			close(f.done)
		}()
	}
	m.mu.Unlock()

	select {
	case <-f.done:
		return f.val, nil
	case <-ctx.Done():
		var zero T
		return zero, ctx.Err()
	}
}

// Forget drops key's cached value, and discards the result of any
// computation already running for it (its waiters still receive it, but it
// is not stored). Call it after an action that changes what the value would
// report, so the next read is fresh.
func (m *Memo[T]) Forget(key string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.m[key]; e != nil {
		e.has = false
		e.gen++
	}
}

// Peek returns key's last cached value without blocking, regardless of its
// age, and whether one exists. It never runs or waits for a computation.
func (m *Memo[T]) Peek(key string) (T, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if e := m.m[key]; e != nil && e.has {
		return e.val, true
	}
	var zero T
	return zero, false
}
