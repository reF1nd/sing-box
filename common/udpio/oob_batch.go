package udpio

import (
	"net"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// OOBPacketBatchReadWaiter receives packet payloads and their associated
// ancillary data in one operation. Returned buffers belong to the caller;
// ancillary-data slices remain valid only until the next wait call.
type OOBPacketBatchReadWaiter interface {
	N.ReadWaitable
	WaitReadOOBPackets() (buffers []*buf.Buffer, oobs [][]byte, sources []M.Socksaddr, err error)
}

// OOBPacketBatchWriter writes one ancillary-data message per packet and takes
// ownership of every buffer, including when the write fails.
type OOBPacketBatchWriter interface {
	WriteOOBPacketBatch(buffers []*buf.Buffer, oobs [][]byte, destinations []M.Socksaddr) error
}

func NewOOBPacketBatchReadWaiter(conn *net.UDPConn, oobSize int) (OOBPacketBatchReadWaiter, bool) {
	return newOOBPacketBatchReadWaiter(conn, oobSize)
}

func NewOOBPacketBatchWriter(conn *net.UDPConn, ipv6 bool) (OOBPacketBatchWriter, bool) {
	return newOOBPacketBatchWriter(conn, ipv6)
}
