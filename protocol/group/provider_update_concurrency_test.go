package group

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	U "github.com/sagernet/sing-box/common/urltest"

	"github.com/stretchr/testify/require"
)

func TestProviderGroupConcurrentUpdates(t *testing.T) {
	firstOutbound := &preMatchTestOutbound{tag: "first/outbound"}
	secondOutbound := &preMatchTestOutbound{tag: "second/outbound"}
	providers := map[string]adapter.Provider{
		"first": &providerUpdateTestProvider{
			tag:       "first",
			outbounds: []adapter.Outbound{firstOutbound},
		},
		"second": &providerUpdateTestProvider{
			tag:       "second",
			outbounds: []adapter.Outbound{secondOutbound},
		},
	}
	outboundManager := &providerUpdateTestOutboundManager{
		outbounds: map[string]adapter.Outbound{
			firstOutbound.Tag():  firstOutbound,
			secondOutbound.Tag(): secondOutbound,
		},
	}
	providerTags := []string{"first", "second"}
	expectedTags := []string{firstOutbound.Tag(), secondOutbound.Tag()}

	t.Run("Selector", func(t *testing.T) {
		selector := &Selector{
			ctx:            context.Background(),
			outbound:       outboundManager,
			tags:           expectedTags,
			outbounds:      outboundManager.outbounds,
			interruptGroup: interrupt.NewGroup(),
			providers:      providers,
			providerTags:   providerTags,
			outboundsCache: make(map[string][]adapter.Outbound),
		}
		selector.selected.Store(firstOutbound)
		runConcurrentProviderUpdates(t, selector.onProviderUpdated, func() {
			_ = selector.All()
			_ = selector.Now()
			selector.SelectOutbound(firstOutbound.Tag())
		})
		require.Equal(t, expectedTags, selector.All())
	})

	t.Run("URLTest", func(t *testing.T) {
		group := &URLTestGroup{
			history:        U.NewHistoryStorage(),
			interruptGroup: interrupt.NewGroup(),
		}
		group.storeOutbounds([]adapter.Outbound{firstOutbound, secondOutbound})
		urlTest := &URLTest{
			outbound:       outboundManager,
			group:          group,
			providers:      providers,
			providerTags:   providerTags,
			outboundsCache: make(map[string][]adapter.Outbound),
		}
		runConcurrentProviderUpdates(t, urlTest.onProviderUpdated, func() {
			_ = urlTest.All()
		})
		require.Equal(t, expectedTags, urlTest.All())
	})

	t.Run("LoadBalance", func(t *testing.T) {
		group := new(LoadBalanceGroup)
		group.storeOutbounds([]adapter.Outbound{firstOutbound, secondOutbound})
		loadBalance := &LoadBalance{
			outbound:       outboundManager,
			group:          group,
			providers:      providers,
			providerTags:   providerTags,
			outboundsCache: make(map[string][]adapter.Outbound),
		}
		runConcurrentProviderUpdates(t, loadBalance.onProviderUpdated, func() {
			_ = loadBalance.All()
		})
		require.Equal(t, expectedTags, loadBalance.All())
	})
}

func TestURLTestProviderUpdateReplacesSelectedOutboundInstance(t *testing.T) {
	previous := &preMatchTestOutbound{tag: "provider/outbound"}
	replacement := &preMatchTestOutbound{tag: previous.Tag()}
	group := &URLTestGroup{
		history:        U.NewHistoryStorage(),
		interruptGroup: interrupt.NewGroup(),
	}
	group.storeOutbounds([]adapter.Outbound{previous})
	group.selectedOutboundTCP.Store(previous)
	group.selectedOutboundUDP.Store(previous)

	group.replaceOutbounds([]adapter.Outbound{replacement})

	require.Same(t, replacement, group.selectedOutboundTCP.Load())
	require.Same(t, replacement, group.selectedOutboundUDP.Load())
}

func TestProviderUpdateCheckCoalescesPendingChecks(t *testing.T) {
	var scheduler providerUpdateCheckScheduler
	var calls atomic.Int32
	firstStarted := make(chan struct{})
	releaseFirst := make(chan struct{})
	finished := make(chan struct{})
	check := func() {
		current := calls.Add(1)
		if current == 1 {
			close(firstStarted)
			<-releaseFirst
		}
		if current == 2 {
			close(finished)
		}
	}

	scheduler.Schedule(check)
	<-firstStarted
	scheduler.Schedule(check)
	scheduler.Schedule(check)
	close(releaseFirst)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for coalesced provider check")
	}
	require.Equal(t, int32(2), calls.Load())
}

func runConcurrentProviderUpdates(t *testing.T, update func(string) error, read func()) {
	t.Helper()
	start := make(chan struct{})
	errors := make(chan error, 2)
	var group sync.WaitGroup
	for _, providerTag := range []string{"first", "second"} {
		providerTag := providerTag
		group.Add(1)
		go func() {
			defer group.Done()
			<-start
			for range 100 {
				if err := update(providerTag); err != nil {
					errors <- err
					return
				}
			}
		}()
	}
	group.Add(1)
	go func() {
		defer group.Done()
		<-start
		for range 200 {
			read()
		}
	}()
	close(start)
	group.Wait()
	close(errors)
	for err := range errors {
		require.NoError(t, err)
	}
}

type providerUpdateTestProvider struct {
	adapter.Provider
	tag       string
	outbounds []adapter.Outbound
}

func (p *providerUpdateTestProvider) Tag() string {
	return p.tag
}

func (p *providerUpdateTestProvider) Outbounds() []adapter.Outbound {
	return p.outbounds
}

type providerUpdateTestOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *providerUpdateTestOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}
