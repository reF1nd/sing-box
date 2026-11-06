//go:build linux || android

package listener

import (
	"os"
	"syscall"

	"github.com/sagernet/sing/common/control"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

const udpSocketBufferSize = 8 << 20

// UDPSocketBufferControl provides the UDP socket-buffer control added to sing
// after the stable dependency revision used by sing-box 1.14.2.
func UDPSocketBufferControl() control.Func {
	return func(network, address string, conn syscall.RawConn) error {
		if N.NetworkName(network) != N.NetworkUDP {
			return nil
		}
		return control.Raw(conn, func(fd uintptr) error {
			err := unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUFFORCE, udpSocketBufferSize)
			if err != nil {
				err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, udpSocketBufferSize)
			}
			if err != nil {
				return os.NewSyscallError("SETSOCKOPT SO_RCVBUF", err)
			}
			err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, udpSocketBufferSize)
			if err != nil {
				err = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_SNDBUF, udpSocketBufferSize)
			}
			if err != nil {
				return os.NewSyscallError("SETSOCKOPT SO_SNDBUF", err)
			}
			return nil
		})
	}
}
