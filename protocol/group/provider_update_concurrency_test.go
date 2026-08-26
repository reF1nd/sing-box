package group

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/interrupt"
	U "github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestSelectorAndURLTestProviderConcurrentUpdates(t *testing.T) {
	firstOutbound := &providerUpdateTestOutbound{tag: "first/outbound"}
	secondOutbound := &providerUpdateTestOutbound{tag: "second/outbound"}
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

}

func TestURLTestProviderUpdateReplacesSelectedOutboundInstance(t *testing.T) {
	previous := &providerUpdateTestOutbound{tag: "provider/outbound"}
	replacement := &providerUpdateTestOutbound{tag: previous.Tag()}
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

func TestURLTestOutboundReturnsWhenDialIgnoresContext(t *testing.T) {
	release := make(chan struct{})
	outbound := &providerUpdateBlockingOutbound{release: release}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := urlTestOutbound(ctx, "http://example.com", outbound)
	close(release)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}

func TestURLTestGroupReturnsWhenDialIgnoresContext(t *testing.T) {
	release := make(chan struct{})
	outbound := &providerUpdateBlockingOutbound{tag: "blocking", release: release}
	outboundManager := &providerUpdateTestOutboundManager{
		outbounds: map[string]adapter.Outbound{outbound.Tag(): outbound},
	}
	group := &URLTestGroup{
		ctx:            context.Background(),
		outbound:       outboundManager,
		logger:         log.NewNOPFactory().NewLogger("urltest"),
		history:        U.NewHistoryStorage(),
		interruptGroup: interrupt.NewGroup(),
	}
	group.storeOutbounds([]adapter.Outbound{outbound})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()

	_, err := group.urlTestWait(ctx, true)
	close(release)
	require.NoError(t, err)
	require.True(t, group.checking.TryLock(), "URLTest checking lock was not released")
	group.checking.Unlock()
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

type providerUpdateTestOutbound struct {
	adapter.Outbound
	tag string
}

type providerUpdateBlockingOutbound struct {
	adapter.Outbound
	tag     string
	release <-chan struct{}
}

func (o *providerUpdateBlockingOutbound) Tag() string {
	return o.tag
}

func (o *providerUpdateBlockingOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (o *providerUpdateBlockingOutbound) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	<-o.release
	return nil, errors.New("released")
}

func (o *providerUpdateTestOutbound) Tag() string {
	return o.tag
}

func (o *providerUpdateTestOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
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
