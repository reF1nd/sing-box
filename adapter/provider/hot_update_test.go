package provider_test

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/adapter/provider"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/urltest"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
)

type nodeOptions struct {
	option.DialerOptions
	Revision int
	Fail     bool
}
type testNode struct {
	outbound.Adapter
	options nodeOptions
	starts  atomic.Int32
	closes  atomic.Int32
	access  sync.Mutex
	conns   []net.Conn
}

func (n *testNode) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	n.starts.Add(1)
	if stage == adapter.StartStateInitialize {
		scope.Add(func() error {
			n.closes.Add(1)
			n.access.Lock()
			defer n.access.Unlock()
			for _, conn := range n.conns {
				conn.Close()
			}
			return nil
		})
	}
	if stage == adapter.StartStateStart && n.options.Fail {
		return errors.New("failed candidate")
	}
	return nil
}
func (n *testNode) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	if n.closes.Load() != 0 {
		return nil, net.ErrClosed
	}
	client, server := net.Pipe()
	n.access.Lock()
	n.conns = append(n.conns, client, server)
	n.access.Unlock()
	go func() { defer server.Close(); io.Copy(server, server) }()
	return client, nil
}
func (*testNode) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errors.New("unsupported")
}

func TestProviderHotUpdateKeepsUnchangedNodesAndConnections(t *testing.T) {
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	factory := log.NewNOPFactory()
	logger := factory.Logger()
	registry := outbound.NewRegistry()
	var candidates []*testNode
	outbound.Register[nodeOptions](registry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options nodeOptions) (adapter.Outbound, error) {
		n := &testNode{Adapter: outbound.NewAdapter("test", tag, []string{"tcp"}, nil), options: options}
		candidates = append(candidates, n)
		return n, nil
	})
	ep := endpoint.NewManager(endpoint.NewRegistry())
	manager := outbound.NewManager(registry, ep, "")
	require.NoError(t, manager.Create(ctx, nil, logger, "static", "test", &nodeOptions{}))
	scope := adapter.NewScope(ctx, logger)
	t.Cleanup(func() { require.NoError(t, scope.Close()) })
	for _, stage := range adapter.ListStartStages {
		require.NoError(t, scope.Start("endpoint", ep, stage))
		require.NoError(t, scope.Start("outbound", manager, stage))
	}
	static, _ := manager.Outbound("static")
	p := provider.NewAdapter(ctx, nil, manager, ep, factory, logger, "subscription", "inline", option.ProviderHealthCheckOptions{})
	require.NoError(t, p.Start())
	t.Cleanup(func() { require.NoError(t, p.Close()) })
	opts := func(stableRev, changedRev int, fail bool) []option.Outbound {
		return []option.Outbound{
			{Type: "test", Tag: "stable", Options: &nodeOptions{Revision: stableRev}},
			{Type: "test", Tag: "changed", Options: &nodeOptions{Revision: changedRev, Fail: fail}},
		}
	}
	initial := opts(1, 1, false)
	p.UpdateNodes(initial, nil)
	stable, _ := p.Outbound("subscription/stable")
	changed, _ := p.Outbound("subscription/changed")
	conn, err := stable.DialContext(ctx, "tcp", M.Socksaddr{})
	require.NoError(t, err)
	defer conn.Close()
	detour := dialer.NewDetour(manager, "subscription/changed", true).(*dialer.DetourDialer)
	first, err := detour.Dialer()
	require.NoError(t, err)
	require.Same(t, changed, first)
	next := opts(1, 2, false)
	p.UpdateNodes(next, nil)
	stableAgain, _ := p.Outbound("subscription/stable")
	changedAgain, _ := p.Outbound("subscription/changed")
	require.Same(t, stable, stableAgain)
	require.NotSame(t, changed, changedAgain)
	require.EqualValues(t, 4, stable.(*testNode).starts.Load())
	require.Zero(t, stable.(*testNode).closes.Load())
	require.EqualValues(t, 1, changed.(*testNode).closes.Load())
	latest, err := detour.Dialer()
	require.NoError(t, err)
	require.Same(t, changedAgain, latest)
	staticAgain, _ := manager.Outbound("static")
	require.Same(t, static, staticAgain)
	require.Zero(t, static.(*testNode).closes.Load())
	require.NoError(t, conn.SetDeadline(time.Now().Add(time.Second)))
	done := make(chan error, 1)
	go func() { _, err := conn.Write([]byte("alive")); done <- err }()
	result := make([]byte, 5)
	_, err = io.ReadFull(conn, result)
	require.NoError(t, err)
	require.NoError(t, <-done)
	require.Equal(t, "alive", string(result))
	failed := opts(1, 3, true)
	p.UpdateNodes(failed, nil)
	retained, _ := p.Outbound("subscription/changed")
	require.Same(t, changedAgain, retained)
	require.EqualValues(t, 1, candidates[len(candidates)-1].closes.Load())
	count := len(candidates)
	p.UpdateNodes(failed, nil)
	require.Len(t, candidates, count+1, "failed updates must be retried")
	p.UpdateNodes(failed[:1], nil)
	_, found := manager.Outbound("subscription/changed")
	require.False(t, found)
	require.EqualValues(t, 1, changedAgain.(*testNode).closes.Load())
	require.NoError(t, p.Close())
	require.NoError(t, scope.Close())
	for _, n := range candidates {
		require.EqualValues(t, 1, n.closes.Load(), n.Tag())
	}
}

func TestProviderEndpointHotUpdate(t *testing.T) {
	ctx := service.ContextWithPtr(context.Background(), urltest.NewHistoryStorage())
	factory := log.NewNOPFactory()
	logger := factory.Logger()
	registry := endpoint.NewRegistry()
	endpoint.Register[nodeOptions](registry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options nodeOptions) (adapter.Endpoint, error) {
		return &testNode{Adapter: outbound.NewAdapter("test", tag, []string{"tcp"}, nil), options: options}, nil
	})
	ep := endpoint.NewManager(registry)
	out := outbound.NewManager(outbound.NewRegistry(), ep, "")
	scope := adapter.NewScope(ctx, logger)
	t.Cleanup(func() { scope.Close() })
	for _, stage := range adapter.ListStartStages {
		require.NoError(t, scope.Start("endpoint", ep, stage))
	}
	p := provider.NewAdapter(ctx, nil, out, ep, factory, logger, "p", "inline", option.ProviderHealthCheckOptions{})
	require.NoError(t, p.Start())
	t.Cleanup(func() { p.Close() })
	initial := []option.Endpoint{{Type: "test", Tag: "a", Options: &nodeOptions{Revision: 1}}}
	p.UpdateNodes(nil, initial)
	old, found := ep.Get("p/a")
	require.True(t, found)
	require.EqualValues(t, 4, old.(*testNode).starts.Load())
	p.UpdateNodes(nil, initial)
	same, _ := ep.Get("p/a")
	require.Same(t, old, same)
	failed := []option.Endpoint{{Type: "test", Tag: "a", Options: &nodeOptions{Fail: true}}}
	p.UpdateNodes(nil, failed)
	same, _ = ep.Get("p/a")
	require.Same(t, old, same)
	next := []option.Endpoint{{Type: "test", Tag: "a", Options: &nodeOptions{Revision: 2}}}
	p.UpdateNodes(nil, next)
	changed, _ := ep.Get("p/a")
	require.NotSame(t, old, changed)
	require.EqualValues(t, 1, old.(*testNode).closes.Load())
	require.NoError(t, p.Close())
	require.EqualValues(t, 1, changed.(*testNode).closes.Load())
	require.NoError(t, scope.Close())
	require.EqualValues(t, 1, changed.(*testNode).closes.Load())
}

func TestProviderOrdersCrossKindDependenciesAndRejectsCycles(t *testing.T) {
	ctx := context.Background()
	factory := log.NewNOPFactory()
	logger := factory.Logger()
	outRegistry, epRegistry := outbound.NewRegistry(), endpoint.NewRegistry()
	ep := endpoint.NewManager(epRegistry)
	out := outbound.NewManager(outRegistry, ep, "")
	var order []string
	makeNode := func(tag string, opts nodeOptions) *testNode {
		if opts.Detour != "" {
			_, found := out.Outbound(opts.Detour)
			require.True(t, found, "dependency must be installed before %s", tag)
		}
		order = append(order, tag)
		return &testNode{Adapter: outbound.NewAdapterWithDialerOptions("test", tag, []string{"tcp"}, opts.DialerOptions), options: opts}
	}
	outbound.Register[nodeOptions](outRegistry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, opts nodeOptions) (adapter.Outbound, error) {
		return makeNode(tag, opts), nil
	})
	endpoint.Register[nodeOptions](epRegistry, "test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, opts nodeOptions) (adapter.Endpoint, error) {
		return makeNode(tag, opts), nil
	})
	p := provider.NewAdapter(ctx, nil, out, ep, factory, logger, "p", "inline", option.ProviderHealthCheckOptions{})
	defer p.Close()
	opts := func(dep string) *nodeOptions { return &nodeOptions{DialerOptions: option.DialerOptions{Detour: dep}} }
	outs := []option.Outbound{{Type: "test", Tag: "last", Options: opts("p/middle")}, {Type: "test", Tag: "first", Options: opts("")}}
	eps := []option.Endpoint{{Type: "test", Tag: "middle", Options: opts("p/first")}}
	require.NoError(t, p.UpdateNodes(outs, eps))
	require.Equal(t, []string{"p/first", "p/middle", "p/last"}, order)
	outs[1].Options = opts("p/last")
	require.ErrorContains(t, p.UpdateNodes(outs, eps), "circular")
	require.Len(t, order, 3, "cycle rejection must not replace existing nodes")
}
