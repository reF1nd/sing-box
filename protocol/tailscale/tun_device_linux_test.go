//go:build with_tailscale && linux

package tailscale

import (
	"bytes"
	"testing"

	singTun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/logger"
	wgTun "github.com/sagernet/wireguard-go/tun"

	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

func TestTunDeviceAdapterReadWithoutGSO(t *testing.T) {
	// Supply raw IP packets through an external descriptor, as a TUN without
	// IFF_VNET_HDR would. This exercises sing-tun's real non-GSO read path
	// without creating a privileged system interface.
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	require.NoError(t, err)
	t.Cleanup(func() { _ = unix.Close(fds[1]) })
	tunDevice, err := singTun.New(singTun.Options{
		FileDescriptor:            fds[0],
		EXP_ExternalConfiguration: true,
	})
	if err != nil {
		_ = unix.Close(fds[0])
		t.Fatal(err)
	}
	t.Cleanup(func() { require.NoError(t, tunDevice.Close()) })
	adapter, err := newTunDeviceAdapter(tunDevice, 1500, logger.NOP())
	require.NoError(t, err)
	require.Equal(t, 1, adapter.BatchSize())
	packet := []byte{
		0x45, 0, 0, 28, 0, 1, 0, 0, 64, 17, 0x8e, 0x99,
		192, 0, 2, 1, 198, 51, 100, 2,
		0x12, 0x34, 0x56, 0x78, 0, 8, 0, 0,
	}
	_, err = unix.Write(fds[1], packet)
	require.NoError(t, err)
	assertAdapterReadPackets(t, adapter, [][]byte{packet})
}

func TestTunDeviceAdapterReadBatch(t *testing.T) {
	packets := [][]byte{{0x45, 1, 2, 3}, {0x60, 4, 5, 6, 7}}
	tunDevice := &batchReadTestTUN{packets: packets}
	adapter, err := newTunDeviceAdapter(tunDevice, 1500, logger.NOP())
	require.NoError(t, err)
	require.Equal(t, len(packets), adapter.BatchSize())
	assertAdapterReadPackets(t, adapter, packets)
}

func assertAdapterReadPackets(t *testing.T, reader interface {
	Read([]byte, []wgTun.ReadPacket) (int, error)
}, packets [][]byte,
) {
	t.Helper()
	const mtu = 1500
	stride := wgTun.ReadPacketSpacing + mtu
	slab := bytes.Repeat([]byte{0xa5}, len(packets)*stride+wgTun.ReadPacketSpacing)
	readPackets := make([]wgTun.ReadPacket, len(packets))
	n, err := reader.Read(slab, readPackets)
	require.NoError(t, err)
	require.Equal(t, len(packets), n)
	for i, packet := range packets {
		expectedOffset := i*stride + wgTun.ReadPacketSpacing
		require.Equal(t, expectedOffset, readPackets[i].Offset)
		require.Equal(t, len(packet), readPackets[i].Size)
		require.Equal(t, packet, slab[readPackets[i].Offset:readPackets[i].Offset+readPackets[i].Size])
		require.Equal(t, bytes.Repeat([]byte{0xa5}, wgTun.ReadPacketSpacing), slab[i*stride:expectedOffset])
	}
}

type batchReadTestTUN struct {
	singTun.LinuxTUN
	packets [][]byte
}

func (t *batchReadTestTUN) BatchSize() int { return len(t.packets) }

func (t *batchReadTestTUN) BatchRead(buffers [][]byte, offset int, sizes []int) (int, error) {
	for i, packet := range t.packets {
		sizes[i] = copy(buffers[i][offset:], packet)
	}
	return len(t.packets), nil
}
