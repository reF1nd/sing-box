package clashmode

import (
	"context"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/service"

	"github.com/stretchr/testify/require"
)

type orderingCacheFile struct {
	adapter.CacheFile
	firstStarted chan struct{}
	releaseFirst chan struct{}
	once         sync.Once
	mu           sync.Mutex
	stored       []string
}

func (c *orderingCacheFile) StoreMode(mode string) error {
	c.once.Do(func() {
		close(c.firstStarted)
		<-c.releaseFirst
	})
	c.mu.Lock()
	c.stored = append(c.stored, mode)
	c.mu.Unlock()
	return nil
}

func TestManagerSetModeSerializesPersistenceOrder(t *testing.T) {
	t.Parallel()
	cache := &orderingCacheFile{
		firstStarted: make(chan struct{}),
		releaseFirst: make(chan struct{}),
	}
	ctx := service.ContextWith[adapter.CacheFile](context.Background(), cache)
	manager := NewManager(ctx, log.NewNOPFactory().Logger(), "Rule", []string{"Rule", "Global", "Direct"})

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		manager.SetMode("Global")
	}()
	<-cache.firstStarted

	wg.Add(1)
	go func() {
		defer wg.Done()
		manager.SetMode("Direct")
	}()

	close(cache.releaseFirst)
	wg.Wait()

	require.Equal(t, "Direct", manager.Mode())
	require.Equal(t, []string{"Global", "Direct"}, cache.stored)
}
