package memo

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestDo_CoalescesConcurrentCallers(t *testing.T) {
	var m Memo[int]
	var calls atomic.Int32
	release := make(chan struct{})
	fn := func(context.Context) int { calls.Add(1); <-release; return 7 }

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v, err := m.Do(context.Background(), "k", time.Minute, fn); err != nil || v != 7 {
				t.Errorf("Do = %d, %v", v, err)
			}
		}()
	}
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()
	if n := calls.Load(); n != 1 {
		t.Fatalf("fn ran %d times, want 1", n)
	}
}

func TestDo_CachesWithinTTLAndRefreshesAfter(t *testing.T) {
	var m Memo[int]
	now := time.Unix(0, 0)
	m.Now = func() time.Time { return now }
	n := 0
	fn := func(context.Context) int { n++; return n }
	get := func() int { v, _ := m.Do(context.Background(), "k", 2*time.Second, fn); return v }

	if get() != 1 || get() != 1 {
		t.Fatal("second call inside the TTL should reuse the first value")
	}
	now = now.Add(3 * time.Second)
	if v := get(); v != 2 {
		t.Fatalf("after TTL got %d, want a fresh value 2", v)
	}
}

func TestForget_DiscardsInFlightResult(t *testing.T) {
	var m Memo[int]
	release := make(chan struct{})
	started := make(chan struct{})
	n := 0
	fn := func(context.Context) int {
		n++
		if n == 1 {
			close(started)
			<-release
		}
		return n
	}
	done := make(chan int)
	go func() { v, _ := m.Do(context.Background(), "k", time.Minute, fn); done <- v }()
	<-started
	m.Forget("k") // state changed while the check was running
	close(release)
	if v := <-done; v != 1 {
		t.Fatalf("waiter got %d, want the in-flight value", v)
	}
	if v, _ := m.Do(context.Background(), "k", time.Minute, fn); v != 2 {
		t.Fatalf("after Forget got %d, want a fresh run (stale in-flight result must not be stored)", v)
	}
}

func TestDo_CallerGivesUpButOthersStillGetValue(t *testing.T) {
	var m Memo[int]
	release := make(chan struct{})
	fn := func(context.Context) int { <-release; return 5 }
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := m.Do(ctx, "k", time.Minute, fn); err == nil {
		t.Fatal("want ctx error when the caller gives up")
	}
	close(release)
	if v, err := m.Do(context.Background(), "k", time.Minute, fn); err != nil || v != 5 {
		t.Fatalf("Do = %d, %v", v, err)
	}
}

func TestDo_ZeroTTLBypasses(t *testing.T) {
	var m Memo[int]
	n := 0
	fn := func(context.Context) int { n++; return n }
	m.Do(context.Background(), "k", 0, fn)
	if v, _ := m.Do(context.Background(), "k", 0, fn); v != 2 {
		t.Fatalf("got %d, want uncached", v)
	}
}

func TestPeek(t *testing.T) {
	var m Memo[int]
	if _, ok := m.Peek("k"); ok {
		t.Fatal("Peek on empty memo reported a value")
	}
	if _, err := m.Do(context.Background(), "k", time.Hour, func(context.Context) int { return 7 }); err != nil {
		t.Fatal(err)
	}
	if v, ok := m.Peek("k"); !ok || v != 7 {
		t.Fatalf("Peek = %d, %v; want 7, true", v, ok)
	}
	m.Forget("k")
	if _, ok := m.Peek("k"); ok {
		t.Fatal("Peek after Forget reported a value")
	}
}
