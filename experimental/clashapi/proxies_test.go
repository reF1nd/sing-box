package clashapi

import (
	"context"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

type blockingDelayOutbound struct {
	tag     string
	started chan struct{}
}

func (o *blockingDelayOutbound) Type() string                                                      { return C.TypeDirect }
func (o *blockingDelayOutbound) Tag() string                                                       { return o.tag }
func (o *blockingDelayOutbound) Network() []string                                                 { return []string{N.NetworkTCP} }
func (o *blockingDelayOutbound) Dependencies() []string                                            { return nil }
func (o *blockingDelayOutbound) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) { return nil, net.ErrClosed }
func (o *blockingDelayOutbound) DialContext(ctx context.Context, _ string, _ M.Socksaddr) (net.Conn, error) {
	select {
	case o.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

type fakeDelayURLTestGroup struct {
	tag          string
	members      []string
	updateChecks atomic.Int32
}

var _ adapter.URLTestGroup = (*fakeDelayURLTestGroup)(nil)

func (g *fakeDelayURLTestGroup) Type() string                                                      { return C.TypeURLTest }
func (g *fakeDelayURLTestGroup) Tag() string                                                       { return g.tag }
func (g *fakeDelayURLTestGroup) Network() []string                                                 { return []string{N.NetworkTCP} }
func (g *fakeDelayURLTestGroup) Dependencies() []string                                            { return g.members }
func (g *fakeDelayURLTestGroup) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) { return nil, net.ErrClosed }
func (g *fakeDelayURLTestGroup) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error)  { return nil, net.ErrClosed }
func (g *fakeDelayURLTestGroup) Selected(string) adapter.Outbound                                  { return nil }
func (g *fakeDelayURLTestGroup) All() []string                                                     { return g.members }
func (g *fakeDelayURLTestGroup) AttachConnection(io.Closer) func()                                 { return func() {} }
func (g *fakeDelayURLTestGroup) URLTest(context.Context) (map[string]uint16, error)                { return nil, nil }
func (g *fakeDelayURLTestGroup) PerformUpdateCheck()                                               { g.updateChecks.Add(1) }

type fakeDelayOutboundManager struct {
	adapter.OutboundManager
	outbounds []adapter.Outbound
	byTag     map[string]adapter.Outbound
}

func (m *fakeDelayOutboundManager) Outbounds() []adapter.Outbound { return m.outbounds }
func (m *fakeDelayOutboundManager) Outbound(tag string) (adapter.Outbound, bool) {
	ob, ok := m.byTag[tag]
	return ob, ok
}

func TestGetProxyDelayCanceledRequestPreservesHistory(t *testing.T) {
	node := &blockingDelayOutbound{tag: "node-1", started: make(chan struct{}, 1)}
	grp := &fakeDelayURLTestGroup{tag: "auto", members: []string{"node-1"}}
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory("node-1", &adapter.URLTestHistory{Time: time.Now(), Delay: 42})

	server := &Server{
		ctx:            context.Background(),
		urlTestHistory: history,
		outbound: &fakeDelayOutboundManager{
			outbounds: []adapter.Outbound{node, grp},
			byTag:     map[string]adapter.Outbound{"node-1": node, "auto": grp},
		},
	}

	reqCtx, cancel := context.WithCancel(context.WithValue(context.Background(), CtxKeyProxy, adapter.Outbound(node)))
	req := httptest.NewRequest(http.MethodGet, "/proxies/node-1/delay?url=https://127.0.0.1/generate_204&timeout=5000", nil).WithContext(reqCtx)
	rec := httptest.NewRecorder()

	done := make(chan struct{})
	go func() {
		defer close(done)
		getProxyDelay(server)(rec, req)
	}()

	select {
	case <-node.started:
	case <-time.After(time.Second):
		t.Fatal("URLTest did not start dialing")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("getProxyDelay did not exit after request cancellation")
	}

	saved := history.LoadURLTestHistory("node-1")
	require.NotNil(t, saved, "canceled delay test must preserve existing history")
	require.Equal(t, uint16(42), saved.Delay)
	require.Zero(t, grp.updateChecks.Load(), "canceled delay test must not trigger PerformUpdateCheck")
}

func TestGetProxyDelayTimeoutUpdatesHistory(t *testing.T) {
	node := &blockingDelayOutbound{tag: "node-1", started: make(chan struct{}, 1)}
	grp := &fakeDelayURLTestGroup{tag: "auto", members: []string{"node-1"}}
	history := urltest.NewHistoryStorage()
	history.StoreURLTestHistory("node-1", &adapter.URLTestHistory{Time: time.Now(), Delay: 42})

	server := &Server{
		ctx:            context.Background(),
		urlTestHistory: history,
		outbound: &fakeDelayOutboundManager{
			outbounds: []adapter.Outbound{node, grp},
			byTag:     map[string]adapter.Outbound{"node-1": node, "auto": grp},
		},
	}

	reqCtx := context.WithValue(context.Background(), CtxKeyProxy, adapter.Outbound(node))
	req := httptest.NewRequest(http.MethodGet, "/proxies/node-1/delay?url=https://127.0.0.1/generate_204&timeout=30", nil).WithContext(reqCtx)
	rec := httptest.NewRecorder()
	getProxyDelay(server)(rec, req)

	require.Equal(t, http.StatusGatewayTimeout, rec.Code)
	require.Nil(t, history.LoadURLTestHistory("node-1"), "timed-out delay test must clear stale history")
	require.Equal(t, int32(1), grp.updateChecks.Load())
}
