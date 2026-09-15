//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/canceler"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type udpNATTestConnection struct {
	conn N.PacketConn
	key  udpSessionKey
}

type udpNATTestHandler struct {
	connections chan udpNATTestConnection
}

func (h *udpNATTestHandler) NewPacketConnectionEx(
	ctx context.Context,
	conn N.PacketConn,
	_ M.Socksaddr,
	_ M.Socksaddr,
	_ N.CloseHandlerFunc,
) {
	key, _ := udpSessionKeyFromContext(ctx)
	h.connections <- udpNATTestConnection{conn: conn, key: key}
}

type udpNATTestWriter struct{}

func (udpNATTestWriter) WritePacket(buffer *buf.Buffer, _ M.Socksaddr) error {
	buffer.Release()
	return nil
}

func TestUDPNATSeparatesEqualSourcesByKernelIdentity(t *testing.T) {
	handler := &udpNATTestHandler{connections: make(chan udpNATTestConnection, 2)}
	service := newUDPNATService(
		handler,
		func(key udpSessionKey, _ M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.WithValue(context.Background(), udpNATContextKey{}, key), udpNATTestWriter{}, nil
		},
		time.Minute,
	)
	t.Cleanup(service.Purge)

	source := M.ParseSocksaddr("192.0.2.10:53000")
	destination := M.ParseSocksaddr("1.1.1.1:53")
	firstKey := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalTC, SocketCookie: 1}
	secondKey := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalTC, SocketCookie: 2}
	service.NewPacket(firstKey, [][]byte{[]byte("first")}, source, destination, nil)
	service.NewPacket(secondKey, [][]byte{[]byte("second")}, source, destination, nil)

	first := receiveUDPNATTestConnection(t, handler.connections)
	second := receiveUDPNATTestConnection(t, handler.connections)
	if first.conn == second.conn {
		t.Fatal("different kernel flow identities shared one UDP NAT connection")
	}
	keys := map[udpSessionKey]bool{first.key: true, second.key: true}
	if !keys[firstKey] || !keys[secondKey] {
		t.Fatalf("handler received unexpected keys: %v %v", first.key, second.key)
	}
	for _, connection := range []udpNATTestConnection{first, second} {
		packet := buf.NewPacket()
		_, err := connection.conn.ReadPacket(packet)
		packet.Release()
		if err != nil {
			t.Fatal(err)
		}
		timeoutConn, loaded := connection.conn.(canceler.PacketConn)
		if !loaded || !timeoutConn.SetTimeout(time.Minute) || timeoutConn.Timeout() <= 0 {
			t.Fatal("UDP NAT connection did not retain timeout control")
		}
	}
}

func receiveUDPNATTestConnection(t *testing.T, connections <-chan udpNATTestConnection) udpNATTestConnection {
	t.Helper()
	select {
	case connection := <-connections:
		return connection
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for UDP NAT connection")
		return udpNATTestConnection{}
	}
}
