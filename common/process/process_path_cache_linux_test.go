//go:build linux

package process

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestProcessPathGlobalHitSkipsUIDScan(t *testing.T) {
	var scopes []uint32
	c := newProcessPathCache(func(_ context.Context, uid uint32) (map[uint32][]string, error) {
		scopes = append(scopes, uid)
		if uid == processPathsAllUsers {
			return map[uint32][]string{1: {"netd"}, 2: {"netd", "helper"}}, nil
		}
		return nil, nil
	})
	defer c.close()
	_, err := c.find(context.Background(), 1, 10001, true)
	require.NoError(t, err)
	paths, err := c.find(context.Background(), 2, 10002, true)
	require.NoError(t, err)
	require.Equal(t, []string{"netd", "helper"}, paths)
	require.Equal(t, []uint32{10001, processPathsAllUsers}, scopes)
}

func TestProcessPathNewInodeAndLoggingBudget(t *testing.T) {
	var calls atomic.Int32
	c := newProcessPathCache(func(_ context.Context, uid uint32) (map[uint32][]string, error) {
		calls.Add(1)
		if uid == processPathsAllUsers {
			return map[uint32][]string{uint32(calls.Load()): {"netd"}}, nil
		}
		return nil, nil
	})
	defer c.close()
	_, err := c.find(context.Background(), 2, 10001, false)
	require.NoError(t, err)
	_, err = c.find(context.Background(), 4, 10001, false)
	require.ErrorIs(t, err, ErrNotFound)
	require.EqualValues(t, 2, calls.Load())
	// A deferred logging lookup must not poison the full lookup's cache.
	paths, err := c.find(context.Background(), 4, 10001, true)
	require.NoError(t, err)
	require.Equal(t, []string{"netd"}, paths)
	require.EqualValues(t, 4, calls.Load())
}

func TestProcessPathNegativeCache(t *testing.T) {
	var calls atomic.Int32
	var clock atomic.Int64
	c := newProcessPathCache(func(context.Context, uint32) (map[uint32][]string, error) { calls.Add(1); return nil, nil })
	c.now = func() time.Time { return time.Unix(0, clock.Load()) }
	defer c.close()
	for range 2 {
		_, err := c.find(context.Background(), 1, 10001, true)
		require.ErrorIs(t, err, ErrNotFound)
	}
	require.EqualValues(t, 2, calls.Load())
	// A different inode is not a cached miss, even within the lifetime.
	_, err := c.find(context.Background(), 2, 10001, true)
	require.ErrorIs(t, err, ErrNotFound)
	require.EqualValues(t, 4, calls.Load())
	clock.Store(int64(processPathMissLifetime + time.Nanosecond))
	_, err = c.find(context.Background(), 1, 10001, true)
	require.ErrorIs(t, err, ErrNotFound)
	require.EqualValues(t, 6, calls.Load())
}

func TestProcessPathConcurrentScanAndCancellation(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	c := newProcessPathCache(func(context.Context, uint32) (map[uint32][]string, error) {
		if calls.Add(1) == 1 {
			close(started)
		}
		<-release
		return map[uint32][]string{1: {"one"}, 2: {"two"}}, nil
	})
	defer c.close()
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := c.find(ctx, 1, 42, true); first <- err }()
	<-started
	cancel()
	require.ErrorIs(t, <-first, context.Canceled)
	var group sync.WaitGroup
	for range 32 {
		group.Go(func() {
			paths, err := c.find(context.Background(), 2, 42, true)
			require.NoError(t, err)
			require.Equal(t, []string{"two"}, paths)
		})
	}
	close(release)
	group.Wait()
	require.EqualValues(t, 1, calls.Load())
}

func TestProcessPathResetDiscardsOldScan(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	c := newProcessPathCache(func(_ context.Context, _ uint32) (map[uint32][]string, error) {
		if calls.Add(1) == 1 {
			close(started)
			<-release
			return map[uint32][]string{1: {"old"}}, nil
		}
		return map[uint32][]string{1: {"new"}}, nil
	})
	defer c.close()
	result := make(chan error, 1)
	go func() { _, err := c.find(context.Background(), 1, 42, true); result <- err }()
	<-started
	c.access.Lock()
	oldScan := c.scans[42]
	c.access.Unlock()
	c.reset()
	require.ErrorIs(t, <-result, context.Canceled)
	paths, err := c.find(context.Background(), 1, 42, true)
	require.NoError(t, err)
	require.Equal(t, []string{"new"}, paths)
	close(release)
	<-oldScan.done
	require.Equal(t, []string{"new"}, c.cached(1, 42))
	c.close()
	_, err = c.find(context.Background(), 1, 42, true)
	require.ErrorIs(t, err, context.Canceled)
}

func TestProcessPathScanErrorIsNotNegativeCached(t *testing.T) {
	var calls atomic.Int32
	failure := errors.New("procfs unavailable")
	c := newProcessPathCache(func(context.Context, uint32) (map[uint32][]string, error) {
		if calls.Add(1) == 1 {
			return nil, failure
		}
		return map[uint32][]string{1: {"ok"}}, nil
	})
	defer c.close()
	_, err := c.find(context.Background(), 1, 42, true)
	require.ErrorIs(t, err, failure)
	paths, err := c.find(context.Background(), 1, 42, true)
	require.NoError(t, err)
	require.Equal(t, []string{"ok"}, paths)
}

func TestProcessPathCacheCapacity(t *testing.T) {
	c := newProcessPathCache(func(context.Context, uint32) (map[uint32][]string, error) { return nil, nil })
	defer c.close()
	for i := range uint32(processPathMissCapacity + 10) {
		_, err := c.find(context.Background(), i, i, true)
		require.ErrorIs(t, err, ErrNotFound)
	}
	c.access.Lock()
	defer c.access.Unlock()
	require.LessOrEqual(t, len(c.snapshots), processPathCapacity)
	require.LessOrEqual(t, len(c.misses), processPathMissCapacity)
}
