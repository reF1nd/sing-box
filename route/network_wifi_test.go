package route

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/settings"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

type stubWIFIMonitor struct {
	callback func(adapter.WIFIState)
	starts   atomic.Int32
	closes   atomic.Int32
}

func (m *stubWIFIMonitor) Start() error {
	m.starts.Add(1)
	if m.callback != nil {
		m.callback(adapter.WIFIState{SSID: "OfficeWiFi"})
	}
	return nil
}

func (m *stubWIFIMonitor) Close() error {
	m.closes.Add(1)
	return nil
}

func (m *stubWIFIMonitor) ReadWIFIState(context.Context) adapter.WIFIState {
	return adapter.WIFIState{SSID: "OfficeWiFi"}
}

type stubWIFIRuleSet struct {
	adapter.RuleSet
	containsWIFI atomic.Bool
}

func (s *stubWIFIRuleSet) Metadata() adapter.RuleSetMetadata {
	return adapter.RuleSetMetadata{ContainsWIFIRule: s.containsWIFI.Load()}
}

func TestNetworkManagerStartsWIFIMonitorOnRuleSetReload(t *testing.T) {
	var created atomic.Int32
	var monitor *stubWIFIMonitor
	nm := &NetworkManager{
		ctx:    context.Background(),
		logger: logger.NOP(),
		newWIFIMonitor: func(_ logger.ContextLogger, cb func(adapter.WIFIState)) (settings.WIFIMonitor, error) {
			created.Add(1)
			monitor = &stubWIFIMonitor{callback: cb}
			return monitor, nil
		},
	}

	rs := &stubWIFIRuleSet{}
	nm.Initialize([]adapter.RuleSet{rs})
	scope := adapter.NewScope(context.Background(), logger.NOP())
	require.NoError(t, nm.Start(adapter.StartStatePostStart, scope))
	require.Zero(t, created.Load(), "Wi-Fi monitor must stay idle when no rule-set uses Wi-Fi conditions")
	require.Empty(t, nm.WIFIState().SSID)

	// Hot reload introduces a Wi-Fi rule; monitor must start once and populate WIFIState.
	rs.containsWIFI.Store(true)
	nm.UpdateRuleSets([]adapter.RuleSet{rs})
	require.Equal(t, int32(1), created.Load())
	require.Equal(t, int32(1), monitor.starts.Load())
	require.Equal(t, "OfficeWiFi", nm.WIFIState().SSID)

	// Subsequent reloads must not duplicate the monitor.
	nm.UpdateRuleSets([]adapter.RuleSet{rs})
	require.Equal(t, int32(1), created.Load())
	require.Equal(t, int32(1), monitor.starts.Load())

	// Scope close stops the dynamically started Wi-Fi monitor cleanly.
	require.NoError(t, scope.Close())
	require.Equal(t, int32(1), monitor.closes.Load())

	// Reloads after close must not recreate the monitor.
	nm.UpdateRuleSets([]adapter.RuleSet{rs})
	require.Equal(t, int32(1), created.Load())
}

func TestNetworkManagerWIFIMonitorConcurrentUpdatesAndClose(t *testing.T) {
	nm := &NetworkManager{
		ctx:    context.Background(),
		logger: logger.NOP(),
		newWIFIMonitor: func(_ logger.ContextLogger, cb func(adapter.WIFIState)) (settings.WIFIMonitor, error) {
			return &stubWIFIMonitor{callback: cb}, nil
		},
	}
	rs := &stubWIFIRuleSet{}
	nm.Initialize([]adapter.RuleSet{rs})
	scope := adapter.NewScope(context.Background(), logger.NOP())
	require.NoError(t, nm.Start(adapter.StartStatePostStart, scope))

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 64; i++ {
			_ = nm.NeedWIFIState()
			nm.UpdateWIFIState(context.Background())
		}
	}()
	rs.containsWIFI.Store(true)
	for i := 0; i < 16; i++ {
		nm.UpdateRuleSets([]adapter.RuleSet{rs})
	}
	require.NoError(t, scope.Close())
	<-done
}
