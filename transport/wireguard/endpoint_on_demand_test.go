package wireguard

import (
	"context"
	"errors"
	"net"
	"testing"

	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

var errOnDemandDeviceReached = errors.New("on-demand device reached")

type onDemandTestDevice struct {
	Device
}

func (*onDemandTestDevice) DialContext(context.Context, string, M.Socksaddr) (net.Conn, error) {
	return nil, errOnDemandDeviceReached
}

func (*onDemandTestDevice) ListenPacket(context.Context, M.Socksaddr) (net.PacketConn, error) {
	return nil, errOnDemandDeviceReached
}

func demandEndpoint(t *testing.T, endpoint *Endpoint, path string) error {
	t.Helper()
	destination := M.ParseSocksaddr("192.0.2.1:443")
	var err error
	switch path {
	case "tcp":
		_, err = endpoint.DialContext(t.Context(), "tcp", destination)
	case "udp":
		_, err = endpoint.ListenPacket(t.Context(), destination)
	case "l3":
		packet := make([]byte, 20)
		packet[0] = 0x45
		err = endpoint.WritePackets([][]byte{packet})
	}
	if errors.Is(err, errOnDemandDeviceReached) {
		return nil
	}
	return err
}

func TestEndpointOnDemandReferenceTransitions(t *testing.T) {
	for _, system := range []bool{false, true} {
		mode := "userspace"
		if system {
			mode = "system"
		}
		for _, path := range []string{"tcp", "udp", "l3"} {
			t.Run(mode+"/"+path, func(t *testing.T) {
				endpoint, pauseManager, bind := newTestEndpoint(t)
				endpoint.options.System = system
				endpoint.tunDevice = &onDemandTestDevice{}
				endpoint.SetIdle(true)
				pauseManager.DevicePause()
				pauseManager.NetworkPause()
				pauseManager.NetworkWake()
				pauseManager.DeviceWake()
				require.NoError(t, endpoint.BindUpdate())
				require.True(t, endpoint.suspended.Load())
				require.EqualValues(t, 1, bind.opens.Load(), "network updates must not wake an idle endpoint")

				// A referenced system interface resumes immediately; a userspace
				// endpoint waits until the next outbound request or packet.
				endpoint.SetIdle(false)
				require.Equal(t, !system, endpoint.suspended.Load())
				if system {
					require.EqualValues(t, 2, bind.opens.Load())
				} else {
					require.EqualValues(t, 1, bind.opens.Load())
				}
				require.NoError(t, demandEndpoint(t, endpoint, path))
				require.False(t, endpoint.suspended.Load())
				require.EqualValues(t, 2, bind.opens.Load())

				endpoint.SetIdle(true)
				require.NoError(t, demandEndpoint(t, endpoint, path))
				require.False(t, endpoint.suspended.Load())
				require.EqualValues(t, 3, bind.opens.Load(), "traffic can resume the endpoint after another idle transition")
			})
		}
	}
}

func TestEndpointOnDemandRetriesFailedStart(t *testing.T) {
	for _, path := range []string{"tcp", "udp", "l3"} {
		t.Run(path, func(t *testing.T) {
			endpoint, _, bind := newTestEndpoint(t)
			endpoint.tunDevice = &onDemandTestDevice{}
			endpoint.SetIdle(true)
			bind.failNext.Store(true)
			require.Error(t, demandEndpoint(t, endpoint, path))
			require.EqualValues(t, 2, bind.opens.Load())
			require.NoError(t, demandEndpoint(t, endpoint, path))
			require.EqualValues(t, 3, bind.opens.Load())
		})
	}
}

func TestEndpointCanceledDemandPreservesIdleDuringNetworkPause(t *testing.T) {
	endpoint, pauseManager, bind := newTestEndpoint(t)
	endpoint.tunDevice = &onDemandTestDevice{}
	endpoint.SetIdle(true)
	pauseManager.NetworkPause()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	destination := M.ParseSocksaddr("192.0.2.1:443")
	_, err := endpoint.DialContext(ctx, "tcp", destination)
	require.ErrorIs(t, err, context.Canceled)
	_, err = endpoint.ListenPacket(ctx, destination)
	require.ErrorIs(t, err, context.Canceled)
	require.ErrorIs(t, demandEndpoint(t, endpoint, "l3"), errNetworkPaused)
	require.True(t, endpoint.suspended.Load())
	pauseManager.NetworkWake()
	require.True(t, endpoint.suspended.Load())
	require.EqualValues(t, 1, bind.opens.Load())
	require.NoError(t, demandEndpoint(t, endpoint, "tcp"))
	require.EqualValues(t, 2, bind.opens.Load())
}
