package dns

import (
	"context"
	"io"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestOutboundNewPacketConnectionCallsOnClose(t *testing.T) {
	outbound := &Outbound{}
	conn := &closedDNSPacketConn{}
	var (
		closeCalls int
		closeErr   error
	)
	outbound.NewPacketConnection(context.Background(), conn, adapter.InboundContext{}, func(err error) {
		closeCalls++
		closeErr = err
	})
	require.Equal(t, 1, closeCalls)
	require.Error(t, closeErr)
	require.Equal(t, 1, conn.closes)
}

type closedDNSPacketConn struct {
	N.PacketConn
	closes int
}

func (*closedDNSPacketConn) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, io.EOF
}

func (c *closedDNSPacketConn) Close() error {
	c.closes++
	return nil
}
