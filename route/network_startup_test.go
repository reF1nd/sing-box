package route

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"

	"github.com/stretchr/testify/require"
)

func TestInterfaceUpdateStartupBoundary(t *testing.T) {
	for _, startedBeforeNotification := range []bool{false, true} {
		name := "notification_during_startup"
		if startedBeforeNotification {
			name = "notification_after_startup"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx = pause.WithDefaultManager(ctx)
			updateLogger := &startupUpdateLogger{
				ContextLogger: log.NewNOPFactory().NewLogger("network"),
				processing:    make(chan struct{}, 1),
			}
			router := new(startupUpdateRouter)
			manager := &NetworkManager{
				ctx: ctx, logger: updateLogger, router: router,
				pauseManager: service.FromContext[pause.Manager](ctx),
				endpoint:     new(startupUpdateEndpoints),
				inbound:      new(startupUpdateInbounds), outbound: new(startupUpdateOutbounds),
			}
			if startedBeforeNotification {
				require.NoError(t, manager.Start(adapter.StartStatePostStart))
			}
			// Hold processing until startup has completed, irrespective of when
			// the notification was received.
			manager.interfaceUpdateRunAccess.Lock()
			manager.notifyInterfaceUpdate(&control.Interface{Name: "test", Index: 1}, 0)
			startErr := manager.Start(adapter.StartStatePostStart)
			manager.interfaceUpdateRunAccess.Unlock()
			require.NoError(t, startErr)
			select {
			case <-updateLogger.processing:
			case <-time.After(5 * time.Second):
				t.Fatal("interface update did not start")
			}
			// The log is emitted while holding this lock, so acquiring it now
			// waits for the update (including any reset) to finish.
			manager.interfaceUpdateRunAccess.Lock()
			resets := router.resets
			manager.interfaceUpdateRunAccess.Unlock()
			if startedBeforeNotification {
				require.Equal(t, 1, resets)
			} else {
				require.Zero(t, resets)
			}
		})
	}
}

type startupUpdateLogger struct {
	logger.ContextLogger
	processing chan struct{}
}

func (l *startupUpdateLogger) Info(...any) { l.processing <- struct{}{} }

type startupUpdateRouter struct {
	adapter.Router
	resets int
}

func (r *startupUpdateRouter) ResetNetwork() { r.resets++ }

type startupUpdateEndpoints struct{ adapter.EndpointManager }

func (*startupUpdateEndpoints) Endpoints() []adapter.Endpoint { return nil }

type startupUpdateInbounds struct{ adapter.InboundManager }

func (*startupUpdateInbounds) Inbounds() []adapter.Inbound { return nil }

type startupUpdateOutbounds struct{ adapter.OutboundManager }

func (*startupUpdateOutbounds) Outbounds() []adapter.Outbound { return nil }
