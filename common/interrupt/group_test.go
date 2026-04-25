package interrupt

import (
	"fmt"
	"github.com/stretchr/testify/require"
	"net"
	"testing"
)

type testGroupConn struct {
	net.Conn
	closed bool
}

func (c *testGroupConn) Close() error { c.closed = true; return nil }

type testGroupPacketConn struct {
	net.PacketConn
	closed bool
}

func (c *testGroupPacketConn) Close() error { c.closed = true; return nil }

func TestGroupResourceDownloadProtection(t *testing.T) {
	for _, external := range []bool{false, true} {
		for _, resourceDownload := range []bool{false, true} {
			for _, interruptExternal := range []bool{false, true} {
				t.Run(fmt.Sprintf("external=%t/download=%t/interrupt=%t", external, resourceDownload, interruptExternal), func(t *testing.T) {
					group := NewGroup()
					tcp := new(testGroupConn)
					udp := new(testGroupPacketConn)
					wrappedTCP := group.NewConn(tcp, external, resourceDownload)
					wrappedUDP := group.NewPacketConn(udp, external, resourceDownload)
					group.Interrupt(interruptExternal)
					expected := !resourceDownload && (!external || interruptExternal)
					require.Equal(t, expected, tcp.closed)
					require.Equal(t, expected, udp.closed)
					require.NoError(t, wrappedTCP.Close())
					require.NoError(t, wrappedUDP.Close())
					require.True(t, tcp.closed)
					require.True(t, udp.closed)
				})
			}
		}
	}
}
