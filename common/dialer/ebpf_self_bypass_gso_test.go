//go:build with_ebpf && (linux || android)

package dialer

import (
	"net"
	"testing"

	"github.com/sagernet/sing/common/bufio"
	N "github.com/sagernet/sing/common/network"
)

func TestSelfBypassGSOPolicyAndCleanup(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		for _, packet := range []bool{false, true} {
			socket, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { socket.Close() })
			var wrapped interface {
				net.Conn
				net.PacketConn
			} = socket
			if disabled {
				wrapped = bufio.NewUDPConnWithoutGSO(socket)
			}
			cleaned := false
			cleanup := func() { cleaned = true }
			var conn interface{ Close() error }
			if packet {
				conn = &selfBypassPacketConn{PacketConn: wrapped, cleanup: cleanup}
			} else {
				raw, rawErr := socket.SyscallConn()
				if rawErr != nil {
					t.Fatal(rawErr)
				}
				conn = &selfBypassConn{Conn: &udpConn{Conn: wrapped, rawConn: raw}, cleanup: cleanup}
			}
			if N.IsGSODisabled(conn) != disabled {
				t.Fatalf("GSO policy lost: disabled=%v packet=%v", disabled, packet)
			}
			if err := conn.Close(); err != nil {
				t.Fatal(err)
			}
			if !cleaned {
				t.Fatal("socket cleanup lost")
			}
		}
	}
}
