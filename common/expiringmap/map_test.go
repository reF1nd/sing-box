package expiringmap

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMapRetainsAllEntriesUntilExpiry(t *testing.T) {
	cache := New[int, string](100 * time.Millisecond)
	t.Cleanup(cache.Close)
	const entryCount = 2048
	for index := range entryCount {
		require.True(t, cache.Store(index, fmt.Sprint(index)))
	}
	require.Equal(t, entryCount, cache.Len())
	value, loaded := cache.Load(0)
	require.True(t, loaded)
	require.Equal(t, "0", value)
	require.Eventually(t, func() bool {
		return cache.Len() == 0
	}, 2*time.Second, 10*time.Millisecond)
	cache.access.Lock()
	require.Zero(t, cache.mapPeak)
	cache.access.Unlock()
}

func TestMapRefreshSurvivesOriginalExpiry(t *testing.T) {
	cache := New[string, string](200 * time.Millisecond)
	t.Cleanup(cache.Close)
	require.True(t, cache.Store("key", "old"))
	time.Sleep(120 * time.Millisecond)
	require.True(t, cache.Store("key", "new"))
	time.Sleep(120 * time.Millisecond)
	value, loaded := cache.Load("key")
	require.True(t, loaded)
	require.Equal(t, "new", value)
	require.Eventually(t, func() bool {
		_, loaded = cache.Load("key")
		return !loaded
	}, 2*time.Second, 10*time.Millisecond)
}

func TestMapLoadAndRefreshSurvivesOriginalExpiry(t *testing.T) {
	cache := New[string, string](200 * time.Millisecond)
	t.Cleanup(cache.Close)
	require.True(t, cache.Store("key", "value"))
	time.Sleep(120 * time.Millisecond)
	value, loaded := cache.LoadAndRefresh("key")
	require.True(t, loaded)
	require.Equal(t, "value", value)
	time.Sleep(120 * time.Millisecond)
	value, loaded = cache.Load("key")
	require.True(t, loaded)
	require.Equal(t, "value", value)
	require.Eventually(t, func() bool {
		return cache.Len() == 0
	}, 2*time.Second, 10*time.Millisecond)
}

func TestMapStoreIfKeepsNewerValue(t *testing.T) {
	cache := New[string, string](time.Second)
	t.Cleanup(cache.Close)
	require.True(t, cache.Store("key", "new"))
	require.False(t, cache.StoreIf("key", "old", func(current string, loaded bool) bool {
		return !loaded || current == "old"
	}))
	value, loaded := cache.Load("key")
	require.True(t, loaded)
	require.Equal(t, "new", value)
}

func TestMapStoreIfTreatsExpiredValueAsAbsent(t *testing.T) {
	cache := New[string, string](20 * time.Millisecond)
	t.Cleanup(cache.Close)
	require.True(t, cache.Store("key", "old"))
	require.Eventually(t, func() bool {
		return cache.Len() == 0
	}, time.Second, 10*time.Millisecond)
	require.True(t, cache.StoreIf("key", "new", func(_ string, loaded bool) bool {
		return !loaded
	}))
	value, loaded := cache.Load("key")
	require.True(t, loaded)
	require.Equal(t, "new", value)
}

func TestMapConcurrentClose(t *testing.T) {
	cache := New[int, int](time.Second)
	var group sync.WaitGroup
	for worker := range 16 {
		group.Add(1)
		go func(worker int) {
			defer group.Done()
			for index := range 256 {
				key := worker*256 + index
				cache.Store(key, key)
				cache.Load(key)
			}
		}(worker)
	}
	group.Wait()
	var closeGroup sync.WaitGroup
	for range 8 {
		closeGroup.Add(1)
		go func() {
			defer closeGroup.Done()
			cache.Close()
		}()
	}
	closeGroup.Wait()
	require.Zero(t, cache.Len())
	require.Nil(t, cache.entries)
	require.False(t, cache.Store(1, 1))
	_, loaded := cache.Load(1)
	require.False(t, loaded)
}
