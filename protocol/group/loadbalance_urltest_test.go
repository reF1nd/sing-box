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
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestLoadBalanceURLTestRecursesAndForcesRefresh(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	leafOne := &loadBalanceURLTestOutbound{tag: "leaf-one"}
	leafTwo := &loadBalanceURLTestOutbound{tag: "leaf-two"}
	nested := &loadBalanceURLTestGroup{tag: "nested", members: []string{leafOne.tag, leafTwo.tag}}
	manager := &loadBalanceURLTestOutboundManager{outbounds: map[string]adapter.Outbound{
		leafOne.tag: leafOne,
		leafTwo.tag: leafTwo,
		nested.tag:  nested,
	}}
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory(leafOne.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 1})
	history.StoreURLTestHistory(leafTwo.tag, &adapter.URLTestHistory{Time: time.Now(), Delay: 1})
	group := &LoadBalanceGroup{
		ctx:       context.Background(),
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
	require.NotContains(t, result, nested.tag)
	require.EqualValues(t, 1, leafOne.dialCount.Load())
	require.EqualValues(t, 1, leafTwo.dialCount.Load())
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
