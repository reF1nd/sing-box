package group

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
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

func TestLoadBalanceURLTestRecursesAndForcesRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		time.Sleep(10 * time.Millisecond)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	leafOne := &loadBalanceURLTestOutbound{tag: "leaf-one"}
	leafTwo := &loadBalanceURLTestOutbound{tag: "leaf-two"}
	manager := &loadBalanceURLTestOutboundManager{outbounds: make(map[string]adapter.Outbound)}
	history := urltest.NewHistoryStorage()
	nestedGroup := &LoadBalanceGroup{
		ctx:       context.Background(),
		tag:       "nested",
		outbound:  manager,
		logger:    log.NewNOPFactory().Logger(),
		outbounds: []adapter.Outbound{leafOne, leafTwo},
		link:      server.URL,
		interval:  time.Hour,
		history:   history,
	}
	nested := &LoadBalance{
		Adapter: adapterOutbound.NewAdapter(C.TypeLoadBalance, nestedGroup.tag, []string{N.NetworkTCP, N.NetworkUDP}, []string{leafOne.tag, leafTwo.tag}),
		group:   nestedGroup,
	}
	manager.outbounds[leafOne.tag] = leafOne
	manager.outbounds[leafTwo.tag] = leafTwo
	manager.outbounds[nested.Tag()] = nested
	history.StoreURLTestHistory(leafOne.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 1})
	history.StoreURLTestHistory(leafTwo.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 1})
	group := &LoadBalanceGroup{
		ctx:       context.Background(),
		tag:       "top",
		outbound:  manager,
		logger:    log.NewNOPFactory().Logger(),
		outbounds: []adapter.Outbound{nested},
		link:      server.URL,
		interval:  time.Hour,
		history:   history,
	}

	result, err := group.URLTest(context.Background())
	require.NoError(t, err)
	require.Contains(t, result, leafOne.tag)
	require.Contains(t, result, leafTwo.tag)
	require.Contains(t, result, nested.Tag())
	require.NotContains(t, result, group.tag)
	require.Equal(t, uint16((uint32(result[leafOne.tag])+uint32(result[leafTwo.tag]))/2), result[nested.Tag()])
	require.Equal(t, result[nested.Tag()], history.LoadURLTestHistory(nested.Tag()).Delay)
	require.Equal(t, result[nested.Tag()], history.LoadURLTestHistory(group.tag).Delay)
	require.EqualValues(t, 1, leafOne.dialCount.Load())
	require.EqualValues(t, 1, leafTwo.dialCount.Load())

	fallback := &loadBalanceURLTestOutbound{tag: "fallback"}
	manager.outbounds[fallback.tag] = fallback
	history.StoreURLTestHistory(fallback.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: result[nested.Tag()] + 100})
	urlTestGroup := &URLTestGroup{
		outbound:  manager,
		outbounds: []adapter.Outbound{nested, fallback},
		history:   history,
	}
	selected, available := urlTestGroup.Select(N.NetworkTCP)
	require.True(t, available)
	require.Same(t, nested, selected)
}

func TestURLTestTriggersNestedLoadBalance(t *testing.T) {
	var outerRequests atomic.Int32
	outerServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		outerRequests.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer outerServer.Close()
	var nestedRequests atomic.Int32
	nestedServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		nestedRequests.Add(1)
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer nestedServer.Close()

	leafOne := &loadBalanceURLTestOutbound{tag: "leaf-one"}
	leafTwo := &loadBalanceURLTestOutbound{tag: "leaf-two"}
	manager := &loadBalanceURLTestOutboundManager{outbounds: make(map[string]adapter.Outbound)}
	history := urltest.NewHistoryStorage()
	nestedGroup := &LoadBalanceGroup{
		ctx:       context.Background(),
		tag:       "nested",
		outbound:  manager,
		logger:    log.NewNOPFactory().Logger(),
		outbounds: []adapter.Outbound{leafOne, leafTwo},
		link:      nestedServer.URL,
		interval:  time.Hour,
		history:   history,
	}
	nested := &LoadBalance{
		Adapter: adapterOutbound.NewAdapter(C.TypeLoadBalance, nestedGroup.tag, []string{N.NetworkTCP, N.NetworkUDP}, []string{leafOne.tag, leafTwo.tag}),
		group:   nestedGroup,
	}
	manager.outbounds[leafOne.tag] = leafOne
	manager.outbounds[leafTwo.tag] = leafTwo
	manager.outbounds[nested.Tag()] = nested

	result := URLTestOutbounds(context.Background(), manager, history, log.NewNOPFactory().Logger(), []adapter.Outbound{nested}, outerServer.URL, time.Hour, true)

	require.Zero(t, outerRequests.Load())
	require.EqualValues(t, 2, nestedRequests.Load())
	require.Contains(t, result, leafOne.tag)
	require.Contains(t, result, leafTwo.tag)
	require.Contains(t, result, nested.Tag())
	require.NotNil(t, history.LoadURLTestHistory(nested.Tag()))
}

func TestLoadBalanceURLTestHistoryUsesOldestLeafTime(t *testing.T) {
	history := urltest.NewHistoryStorage()
	oldestTime := time.Now().Add(-time.Hour)
	newestTime := time.Now()

	groupHistory := updateLoadBalanceURLTestHistoryFromLeaves(history, "load-balance", map[string]*adapter.URLTestHistory{
		"old": {Time: oldestTime, Delay: 100},
		"new": {Time: newestTime, Delay: 200},
	})

	require.NotNil(t, groupHistory)
	require.Equal(t, oldestTime, groupHistory.Time)
	require.Equal(t, uint16(150), groupHistory.Delay)
}

func TestLoadBalanceURLTestDeletesStaleGroupHistory(t *testing.T) {
	nested := &loadBalanceURLTestGroup{tag: "nested", members: []string{"missing"}}
	manager := &loadBalanceURLTestOutboundManager{outbounds: map[string]adapter.Outbound{nested.tag: nested}}
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory(nested.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 1})
	history.StoreURLTestHistory("top", &adapter.URLTestHistory{Time: time.Now(), Delay: 1})

	require.Nil(t, updateLoadBalanceURLTestHistory(manager, history, "top", []adapter.Outbound{nested}))
	require.Nil(t, history.LoadURLTestHistory(nested.tag))
	require.Nil(t, history.LoadURLTestHistory("top"))

	cycleOne := &loadBalanceURLTestGroup{tag: "cycle-one", members: []string{"cycle-two"}}
	cycleTwo := &loadBalanceURLTestGroup{tag: "cycle-two", members: []string{"cycle-one"}}
	manager.outbounds[cycleOne.tag] = cycleOne
	manager.outbounds[cycleTwo.tag] = cycleTwo
	history.StoreURLTestHistory(cycleOne.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 1})
	history.StoreURLTestHistory(cycleTwo.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 1})
	require.Nil(t, updateLoadBalanceURLTestHistory(manager, history, cycleOne.tag, []adapter.Outbound{cycleOne}))
	require.Nil(t, history.LoadURLTestHistory(cycleOne.tag))
	require.Nil(t, history.LoadURLTestHistory(cycleTwo.tag))
}

func TestLoadBalanceURLTestUsesCallerContext(t *testing.T) {
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseDial := func() { releaseOnce.Do(func() { close(release) }) }
	timer := time.AfterFunc(500*time.Millisecond, releaseDial)
	defer func() {
		timer.Stop()
		releaseDial()
	}()

	leaf := &loadBalanceURLTestOutbound{tag: "leaf", release: release}
	manager := &loadBalanceURLTestOutboundManager{outbounds: map[string]adapter.Outbound{leaf.tag: leaf}}
	group := &LoadBalanceGroup{
		ctx:       context.Background(),
		outbound:  manager,
		logger:    log.NewNOPFactory().Logger(),
		outbounds: []adapter.Outbound{leaf},
		link:      "http://example.com",
		interval:  time.Hour,
		history:   urltest.NewHistoryStorage(),
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	startedAt := time.Now()
	result, err := group.URLTest(ctx)
	elapsed := time.Since(startedAt)
	releaseDial()

	require.NoError(t, err)
	require.Empty(t, result)
	require.Less(t, elapsed, 300*time.Millisecond)
	require.EqualValues(t, 1, leaf.dialCount.Load())
}

func TestLoadBalanceAliveForNestedLoadBalance(t *testing.T) {
	leaf := &loadBalanceURLTestOutbound{tag: "leaf"}
	nestedInner := &loadBalanceURLTestGroup{tag: "nested-inner", members: []string{leaf.tag}}
	nestedOuter := &loadBalanceURLTestGroup{tag: "nested-outer", members: []string{nestedInner.tag}}
	manager := &loadBalanceURLTestOutboundManager{outbounds: map[string]adapter.Outbound{
		leaf.tag:        leaf,
		nestedInner.tag: nestedInner,
		nestedOuter.tag: nestedOuter,
	}}
	history := urltest.NewHistoryStorage()
	group := &LoadBalanceGroup{outbound: manager, history: history}

	require.False(t, group.AliveForTestUrl(nestedOuter))
	history.StoreURLTestHistory(leaf.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 1})
	require.True(t, group.AliveForTestUrl(nestedOuter))

	cycleOne := &loadBalanceURLTestGroup{tag: "cycle-one", members: []string{"cycle-two"}}
	cycleTwo := &loadBalanceURLTestGroup{tag: "cycle-two", members: []string{"cycle-one"}}
	manager.outbounds[cycleOne.tag] = cycleOne
	manager.outbounds[cycleTwo.tag] = cycleTwo
	require.False(t, group.AliveForTestUrl(cycleOne))
}

type loadBalanceURLTestOutbound struct {
	adapter.Outbound
	tag       string
	release   <-chan struct{}
	dialCount atomic.Int32
}

func (o *loadBalanceURLTestOutbound) Tag() string {
	return o.tag
}

func (o *loadBalanceURLTestOutbound) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (o *loadBalanceURLTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.dialCount.Add(1)
	if o.release != nil {
		<-o.release
		return nil, ctx.Err()
	}
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}

type loadBalanceURLTestGroup struct {
	adapter.Outbound
	tag     string
	members []string
}

func (g *loadBalanceURLTestGroup) Tag() string {
	return g.tag
}

func (g *loadBalanceURLTestGroup) Network() []string {
	return []string{N.NetworkTCP, N.NetworkUDP}
}

func (g *loadBalanceURLTestGroup) Now() string {
	return ""
}

func (g *loadBalanceURLTestGroup) All() []string {
	return g.members
}

func (g *loadBalanceURLTestGroup) URLTest(context.Context) (map[string]uint16, error) {
	return nil, nil
}

type loadBalanceURLTestOutboundManager struct {
	adapter.OutboundManager
	outbounds map[string]adapter.Outbound
}

func (m *loadBalanceURLTestOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	outbound, loaded := m.outbounds[tag]
	return outbound, loaded
}
