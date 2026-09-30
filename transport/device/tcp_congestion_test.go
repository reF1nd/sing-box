package device

import (
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"

	"github.com/stretchr/testify/require"
)

func TestStackTCPCongestionControl(t *testing.T) {
	for _, algorithm := range []string{"", "reno", "cubic", "bbr", "invalid"} {
		t.Run(algorithm, func(t *testing.T) {
			memoryTun := tun.NewMemoryTun(tun.MemoryTunOptions{MTU: 1280})
			defer memoryTun.Close()
			stack, err := newStack(Options{
				Context:              t.Context(),
				Logger:               log.NewNOPFactory().Logger(),
				MTU:                  1280,
				TCPCongestionControl: algorithm,
			}, memoryTun)
			if algorithm == "invalid" {
				// Rejection by sing-tun proves the option reached the actual TCP stack.
				require.ErrorContains(t, err, "unknown congestion control")
				return
			}
			require.NoError(t, err)
			require.NoError(t, stack.Close())
		})
	}
}
