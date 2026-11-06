//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
)

func TestProcessInfoCacheLifetime(t *testing.T) {
	cache := newProcessInfoCache()
	now := time.Unix(100, 0)
	key := processInfoCacheKey{processID: 42, userID: 1000}
	info := &adapter.ConnectionOwner{ProcessID: 42, UserId: 1000, ProcessPath: "/bin/client", AndroidPackageNames: []string{"client"}}
	cache.store(key, info, nil, now)

	loaded, err, ok := cache.load(key, now.Add(processInfoCacheLifetime/2))
	if !ok || err != nil || loaded != info {
		t.Fatalf("cache load = (%v, %v, %t), want stored process info", loaded, err, ok)
	}
	if _, _, ok = cache.load(key, now.Add(processInfoCacheLifetime)); ok {
		t.Fatal("expired process info remained cached")
	}
}

func TestProcessInfoCacheReusesFailedLookup(t *testing.T) {
	cache := newProcessInfoCache()
	key := processInfoCacheKey{processID: 42, userID: 1000}
	info := &adapter.ConnectionOwner{ProcessID: 42, UserId: 1000}
	wantErr := errors.New("process exited")
	var lookupCount int
	resolve := func() (*adapter.ConnectionOwner, error) {
		lookupCount++
		return info, wantErr
	}

	firstInfo, firstErr, firstResolved := cache.loadOrResolve(key, resolve)
	secondInfo, secondErr, secondResolved := cache.loadOrResolve(key, resolve)
	if firstInfo != info || !errors.Is(firstErr, wantErr) || !firstResolved {
		t.Fatalf("first lookup = (%v, %v, %t), want resolved failure", firstInfo, firstErr, firstResolved)
	}
	if secondInfo != info || !errors.Is(secondErr, wantErr) || secondResolved {
		t.Fatalf("second lookup = (%v, %v, %t), want cached failure", secondInfo, secondErr, secondResolved)
	}
	if lookupCount != 1 {
		t.Fatalf("process resolver called %d times, want 1", lookupCount)
	}
}

func TestProcessInfoNegativeCacheLifetime(t *testing.T) {
	cache := newProcessInfoCache()
	now := time.Unix(100, 0)
	key := processInfoCacheKey{processID: 42, userID: 1000}
	info := &adapter.ConnectionOwner{ProcessID: 42, UserId: 1000}
	wantErr := errors.New("process exited")
	cache.store(key, info, wantErr, now)

	loaded, err, ok := cache.load(key, now.Add(processInfoNegativeCacheLifetime/2))
	if !ok || !errors.Is(err, wantErr) || loaded != info {
		t.Fatalf("negative cache load = (%v, %v, %t), want stored partial process info and error", loaded, err, ok)
	}
	if _, _, ok = cache.load(key, now.Add(processInfoNegativeCacheLifetime)); ok {
		t.Fatal("expired negative process info remained cached")
	}
}

func TestProcessInfoCacheIsBounded(t *testing.T) {
	cache := newProcessInfoCache()
	now := time.Unix(100, 0)
	info := &adapter.ConnectionOwner{ProcessPath: "/bin/client"}
	for processID := uint32(0); processID < processInfoCacheCapacity+32; processID++ {
		cache.store(processInfoCacheKey{processID: processID}, info, nil, now)
	}
	cache.access.Lock()
	size := len(cache.entries)
	cache.access.Unlock()
	if size > processInfoCacheCapacity {
		t.Fatalf("cache size = %d, want <= %d", size, processInfoCacheCapacity)
	}
}

func TestProcessInfoCacheCombinesConcurrentMisses(t *testing.T) {
	const callers = 32
	cache := newProcessInfoCache()
	key := processInfoCacheKey{processID: 42, userID: 1000}
	info := &adapter.ConnectionOwner{ProcessID: 42, UserId: 1000, ProcessPath: "/bin/client"}
	lookupStarted := make(chan struct{})
	releaseLookup := make(chan struct{})
	var lookupCount atomic.Int32
	resolve := func() (*adapter.ConnectionOwner, error) {
		if lookupCount.Add(1) == 1 {
			close(lookupStarted)
		}
		<-releaseLookup
		return info, nil
	}

	start := make(chan struct{})
	results := make(chan *adapter.ConnectionOwner, callers)
	resolved := make(chan bool, callers)
	var ready sync.WaitGroup
	ready.Add(callers)
	for range callers {
		go func() {
			ready.Done()
			<-start
			result, err, performed := cache.loadOrResolve(key, resolve)
			if err != nil {
				t.Errorf("loadOrResolve: %v", err)
			}
			results <- result
			resolved <- performed
		}()
	}
	ready.Wait()
	close(start)
	<-lookupStarted

	deadline := time.Now().Add(time.Second)
	for {
		cache.access.Lock()
		lookup := cache.inFlight[key]
		allJoined := lookup != nil && lookup.waiters == callers-1
		cache.access.Unlock()
		if allJoined {
			break
		}
		if time.Now().After(deadline) {
			close(releaseLookup)
			t.Fatal("concurrent process lookups did not join the in-flight lookup")
		}
		time.Sleep(time.Millisecond)
	}
	close(releaseLookup)

	performedCount := 0
	for range callers {
		if result := <-results; result != info {
			t.Fatalf("resolved process info = %v, want shared result", result)
		}
		if <-resolved {
			performedCount++
		}
	}
	if count := lookupCount.Load(); count != 1 {
		t.Fatalf("process resolver called %d times, want 1", count)
	}
	if performedCount != 1 {
		t.Fatalf("performed result reported %d times, want 1", performedCount)
	}
}
