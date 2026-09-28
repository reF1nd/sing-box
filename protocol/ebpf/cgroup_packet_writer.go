//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"os"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Cgroup replies use token-source packet info on the original listener.
// Socket-assignment replies instead use sockets in the private namespace.
// Choose the strategy once when the UDP session is created.
type cgroupPacketWriter struct {
	inbound     *Inbound
	key         udpSessionKey
	clientState *udpClientState
}

func (w *cgroupPacketWriter) ensureReplyBinding(destination netip.AddrPort) (udpRedirectBinding, error) {
	if binding, loaded := w.clientState.redirectBinding(destination); loaded {
		return binding, nil
	}
	backend := w.inbound.cgroupBackendInstance()
	if backend == nil {
		return udpRedirectBinding{}, E.New("cgroup eBPF backend is closed")
	}
	redirect, err := backend.ReserveUDPReplyRedirect(destination, w.inbound.listeners.selectedPort())
	if err != nil {
		return udpRedirectBinding{}, err
	}
	if !w.inbound.udpClientTable.setCgroupReplyBinding(w.key, w.clientState, destination, redirect) {
		_ = backend.DeleteRedirect(commonEBPF.ProtocolUDP, netip.AddrPortFrom(redirect, w.inbound.listeners.selectedPort()))
		return udpRedirectBinding{}, E.New("cgroup eBPF UDP reply binding was rejected")
	}
	binding, loaded := w.clientState.redirectBinding(destination)
	if !loaded {
		return udpRedirectBinding{}, E.New("cgroup eBPF UDP reply binding is unavailable")
	}
	return binding, nil
}

func (w *cgroupPacketWriter) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	binding, err := w.ensureReplyBinding(destination.AddrPort())
	if err != nil {
		return err
	}
	return w.inbound.listeners.writeUDP(buffer.Bytes(), binding.packetInfo, w.key.Source, binding.redirectAddress)
}

func (w *cgroupPacketWriter) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	if len(buffers) == 0 || len(buffers) != len(destinations) {
		buf.ReleaseMulti(buffers)
		return os.ErrInvalid
	}
	packetInfos := make([][]byte, len(buffers))
	sources := make([]netip.Addr, len(buffers))
	for index, destination := range destinations {
		binding, err := w.ensureReplyBinding(destination.AddrPort())
		if err != nil {
			buf.ReleaseMulti(buffers)
			return err
		}
		packetInfos[index] = binding.packetInfo
		sources[index] = binding.redirectAddress
	}
	return w.inbound.listeners.writeUDPBatch(buffers, packetInfos, w.key.Source, sources)
}

var _ N.PacketBatchWriter = (*cgroupPacketWriter)(nil)
