//go:build !linux

package udpio

import "net"

func newOOBPacketBatchReadWaiter(*net.UDPConn, int) (OOBPacketBatchReadWaiter, bool) {
	return nil, false
}

func newOOBPacketBatchWriter(*net.UDPConn, bool) (OOBPacketBatchWriter, bool) {
	return nil, false
}
