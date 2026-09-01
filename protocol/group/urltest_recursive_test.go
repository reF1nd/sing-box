package group

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	adapterOutbound "github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestURLTestDeduplicatesSameLeafAndURLAcrossNestedGroups(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	leaf := &recursiveURLTestOutbound{tag: "leaf"}
	manager := &recursiveURLTestOutboundManager{outbounds: make(map[string]adapter.Outbound)}
	history := urltest.NewHistoryStorage()
	firstGroup := newURLTestForRecursiveTest("first", server.URL, manager, history, leaf)
	secondGroup := newURLTestForRecursiveTest("second", server.URL, manager, history, leaf)
	manager.outbounds[leaf.tag] = leaf
	manager.outbounds[firstGroup.Tag()] = firstGroup
	manager.outbounds[secondGroup.Tag()] = secondGroup

	result := URLTestOutbounds(context.Background(), manager, history, log.NewNOPFactory().Logger(), []adapter.Outbound{firstGroup, secondGroup}, "", time.Hour, true)

	require.EqualValues(t, 1, leaf.dialCount.Load())
	require.EqualValues(t, 1, requests.Load())
	require.Contains(t, result, leaf.tag)
	require.Contains(t, result, firstGroup.Tag())
	require.Contains(t, result, secondGroup.Tag())
}

func TestURLTestDoesNotDeduplicateDifferentURLs(t *testing.T) {
	var firstRequests atomic.Int32
	firstServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		firstRequests.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer firstServer.Close()
	var secondRequests atomic.Int32
	secondServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		secondRequests.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer secondServer.Close()

	leaf := &recursiveURLTestOutbound{tag: "leaf"}
	manager := &recursiveURLTestOutboundManager{outbounds: make(map[string]adapter.Outbound)}
	history := urltest.NewHistoryStorage()
	firstGroup := newURLTestForRecursiveTest("first", firstServer.URL, manager, history, leaf)
	secondGroup := newURLTestForRecursiveTest("second", secondServer.URL, manager, history, leaf)
	manager.outbounds[leaf.tag] = leaf
	manager.outbounds[firstGroup.Tag()] = firstGroup
	manager.outbounds[secondGroup.Tag()] = secondGroup

	URLTestOutbounds(context.Background(), manager, history, log.NewNOPFactory().Logger(), []adapter.Outbound{firstGroup, secondGroup}, "", time.Hour, true)

	require.EqualValues(t, 2, leaf.dialCount.Load())
	require.EqualValues(t, 1, firstRequests.Load())
	require.EqualValues(t, 1, secondRequests.Load())
}

func TestURLTestSelectionKeepsCurrentWithinTolerance(t *testing.T) {
	current := &recursiveURLTestOutbound{tag: "current"}
	candidate := &recursiveURLTestOutbound{tag: "candidate"}
	manager := &recursiveURLTestOutboundManager{outbounds: map[string]adapter.Outbound{
		current.tag:   current,
		candidate.tag: candidate,
	}}
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory(current.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
	history.StoreURLTestHistory(candidate.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 60})
	group := &URLTestGroup{
		outbound:  manager,
		outbounds: []adapter.Outbound{current, candidate},
		history:   history,
		tolerance: 50,
	}
	group.selectedOutboundTCP.Store(current)

	selected, available := group.Select(N.NetworkTCP)
	require.True(t, available)
	require.Same(t, current, selected)

	history.StoreURLTestHistory(candidate.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 49})
	selected, available = group.Select(N.NetworkTCP)
	require.True(t, available)
	require.Same(t, candidate, selected)
}

func TestURLTestFallbackSelectsFirstAvailable(t *testing.T) {
	first := &recursiveURLTestOutbound{tag: "first"}
	second := &recursiveURLTestOutbound{tag: "second"}
	manager := &recursiveURLTestOutboundManager{outbounds: map[string]adapter.Outbound{
		first.tag:  first,
		second.tag: second,
	}}
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory(first.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 100})
	history.StoreURLTestHistory(second.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 20})
	group := &URLTestGroup{
		outbound:  manager,
		outbounds: []adapter.Outbound{first, second},
		history:   history,
		fallback:  URLTestFallback{enabled: true},
	}

	selected, available := group.Select(N.NetworkTCP)
	require.True(t, available)
	require.Same(t, first, selected)
}

type recursiveURLTestOutbound struct {
	adapter.Outbound
	tag       string
	dialCount atomic.Int32
}

func (o *recursiveURLTestOutbound) Tag() string {
	return o.tag
}

func (o *recursiveURLTestOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (o *recursiveURLTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.dialCount.Add(1)
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

type recursiveURLTestOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *recursiveURLTestOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}

func newURLTestForRecursiveTest(tag string, link string, manager adapter.OutboundManager, history *urltest.HistoryStorage, outbounds ...adapter.Outbound) *URLTest {
	memberTags := make([]string, 0, len(outbounds))
	for _, member := range outbounds {
		memberTags = append(memberTags, member.Tag())
	}
	group := &URLTestGroup{
		ctx:       context.Background(),
		outbound:  manager,
		logger:    log.NewNOPFactory().Logger(),
		outbounds: outbounds,
		link:      link,
		interval:  time.Hour,
		history:   history,
	}
	return &URLTest{
		Adapter: adapterOutbound.NewAdapter(C.TypeURLTest, tag, []string{N.NetworkTCP, N.NetworkUDP}, memberTags),
		group:   group,
	}
}
