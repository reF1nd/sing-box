//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// Namespace listeners never infer cgroup redirects from a destination prefix.
// Their TCP and UDP tuples always belong to the socket-assignment data plane.
type tcListenerHandler struct{ inbound *Inbound }

func (h tcListenerHandler) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	backend := h.inbound.tcBackend()
	if backend == nil {
		_ = conn.Close()
		return
	}
	h.inbound.newTCConnection(ctx, backend, conn, metadata, onClose)
}

func (h tcListenerHandler) NewPacket(buffer *buf.Buffer, oob []byte, source M.Socksaddr) {
	if backend := h.inbound.tcBackend(); backend != nil {
		h.inbound.newTCPacket(backend, buffer, oob, source, false)
	}
}

func (h tcListenerHandler) NewOOBPacketBatch(buffers []*buf.Buffer, oobs [][]byte, sources []M.Socksaddr) {
	backend := h.inbound.tcBackend()
	if backend == nil || len(buffers) != len(oobs) || len(buffers) != len(sources) {
		buf.ReleaseMulti(buffers)
		return
	}
	for index, buffer := range buffers {
		if !h.inbound.newTCPacket(backend, buffer, oobs[index], sources[index], true) {
			buffer.Release()
		}
	}
}
