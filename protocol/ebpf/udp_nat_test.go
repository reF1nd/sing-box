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

type udpNATTestPacket struct {
	buffer      *buf.Buffer
	destination M.Socksaddr
}

type udpNATTestPacketHandler struct {
	packets       chan udpNATTestPacket
	frontHeadroom int
}

func (h *udpNATTestPacketHandler) NewPacketEx(buffer *buf.Buffer, destination M.Socksaddr) {
	h.packets <- udpNATTestPacket{buffer: buffer, destination: destination}
}

func (h *udpNATTestPacketHandler) FrontHeadroom() int {
	return h.frontHeadroom
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

func TestUDPNATOwnedPacketReleasedWhenPrepareRejects(t *testing.T) {
	service := newUDPNATService(
		&udpNATTestHandler{connections: make(chan udpNATTestConnection, 1)},
		func(udpSessionKey, M.Socksaddr, M.Socksaddr, any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return false, nil, nil, nil
		},
		time.Minute,
	)
	t.Cleanup(service.Purge)

	buffer := buf.NewPacket()
	_, _ = buffer.WriteString("rejected")
	service.NewPacketBuffer(
		udpSessionKey{Source: M.ParseSocksaddr("192.0.2.10:53000").AddrPort(), Scope: udpSessionScopeLocalTC},
		buffer,
		M.ParseSocksaddr("192.0.2.10:53000"),
		M.ParseSocksaddr("1.1.1.1:53"),
		nil,
	)
	if buffer.Cap() != 0 {
		t.Fatal("rejected owned packet was not released")
	}
}

func TestUDPNATOwnedPacketReusesCompatibleBuffer(t *testing.T) {
	connections := make(chan udpNATTestConnection, 1)
	service := newUDPNATService(
		&udpNATTestHandler{connections: connections},
		func(key udpSessionKey, _ M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.WithValue(context.Background(), udpNATContextKey{}, key), udpNATTestWriter{}, nil
		},
		time.Minute,
	)
	t.Cleanup(service.Purge)

	source := M.ParseSocksaddr("192.0.2.10:53000")
	destination := M.ParseSocksaddr("1.1.1.1:53")
	key := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalTC}
	service.NewPacket(key, [][]byte{[]byte("initial")}, source, destination, nil)
	connection := receiveUDPNATTestConnection(t, connections)
	handler := &udpNATTestPacketHandler{packets: make(chan udpNATTestPacket, 2)}
	connection.conn.(*udpNATConn).SetHandler(handler)
	initial := <-handler.packets
	initial.buffer.Release()

	buffer := buf.NewPacket()
	_, _ = buffer.WriteString("owned")
	service.NewPacketBuffer(key, buffer, source, destination, nil)
	packet := <-handler.packets
	if packet.buffer != buffer {
		t.Fatal("compatible owned packet buffer was copied")
	}
	if string(packet.buffer.Bytes()) != "owned" || packet.destination != destination {
		t.Fatalf("unexpected packet: payload=%q destination=%v", packet.buffer.Bytes(), packet.destination)
	}
	packet.buffer.Release()
}

func TestUDPNATQueuedOwnedPacketAddsRequiredHeadroom(t *testing.T) {
	connections := make(chan udpNATTestConnection, 1)
	service := newUDPNATService(
		&udpNATTestHandler{connections: connections},
		func(key udpSessionKey, _ M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.WithValue(context.Background(), udpNATContextKey{}, key), udpNATTestWriter{}, nil
		},
		time.Minute,
	)
	t.Cleanup(service.Purge)

	source := M.ParseSocksaddr("192.0.2.10:53000")
	destination := M.ParseSocksaddr("1.1.1.1:53")
	key := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalTC}
	buffer := buf.NewPacket()
	_, _ = buffer.WriteString("queued")
	service.NewPacketBuffer(key, buffer, source, destination, nil)
	connection := receiveUDPNATTestConnection(t, connections)
	handler := &udpNATTestPacketHandler{
		packets:       make(chan udpNATTestPacket, 1),
		frontHeadroom: 32,
	}
	connection.conn.(*udpNATConn).SetHandler(handler)
	packet := <-handler.packets
	if packet.buffer == buffer {
		t.Fatal("owned packet without required headroom was not copied")
	}
	if buffer.Cap() != 0 {
		t.Fatal("source buffer was not released after adding headroom")
	}
	if packet.buffer.Start() < handler.frontHeadroom || string(packet.buffer.Bytes()) != "queued" {
		t.Fatalf("invalid copied packet: start=%d payload=%q", packet.buffer.Start(), packet.buffer.Bytes())
	}
	packet.buffer.Release()
}

func TestUDPNATOwnedPacketReleasedWhenQueueIsFull(t *testing.T) {
	connections := make(chan udpNATTestConnection, 1)
	service := newUDPNATService(
		&udpNATTestHandler{connections: connections},
		func(key udpSessionKey, _ M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.WithValue(context.Background(), udpNATContextKey{}, key), udpNATTestWriter{}, nil
		},
		time.Minute,
	)
	t.Cleanup(service.Purge)

	source := M.ParseSocksaddr("192.0.2.10:53000")
	destination := M.ParseSocksaddr("1.1.1.1:53")
	key := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalTC}
	for range 64 {
		buffer := buf.NewPacket()
		service.NewPacketBuffer(key, buffer, source, destination, nil)
	}
	connection := receiveUDPNATTestConnection(t, connections)
	natConn := connection.conn.(*udpNATConn)
	if len(natConn.packetChan) != cap(natConn.packetChan) {
		t.Fatalf("packet queue length = %d, want %d", len(natConn.packetChan), cap(natConn.packetChan))
	}
	overflow := buf.NewPacket()
	_, _ = overflow.WriteString("overflow")
	service.NewPacketBuffer(key, overflow, source, destination, nil)
	if overflow.Cap() != 0 {
		t.Fatal("owned packet dropped from a full queue was not released")
	}
	for range 64 {
		packet := <-natConn.packetChan
		packet.Buffer.Release()
		N.PutPacketBuffer(packet)
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
