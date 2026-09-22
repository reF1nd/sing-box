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

type udpNATClosingPacketHandler struct {
	conn  N.PacketConn
	calls int
}

func (h *udpNATClosingPacketHandler) NewPacketEx(buffer *buf.Buffer, _ M.Socksaddr) {
	h.calls++
	buffer.Release()
	_ = h.conn.Close()
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
	t.Cleanup(func() { _ = service.Close() })

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
	t.Cleanup(func() { _ = service.Close() })

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
	t.Cleanup(func() { _ = service.Close() })

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
	t.Cleanup(func() { _ = service.Close() })

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
	t.Cleanup(func() { _ = service.Close() })

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
	if diagnostics := service.diagnostics(); diagnostics.QueueDrops != 1 {
		t.Fatalf("queue drops = %d, want 1", diagnostics.QueueDrops)
	}
	for range 64 {
		packet := <-natConn.packetChan
		packet.Buffer.Release()
		N.PutPacketBuffer(packet)
	}
}

func TestUDPNATDiagnosticsReuseCacheMetrics(t *testing.T) {
	connections := make(chan udpNATTestConnection, 1025)
	service := newUDPNATService(
		&udpNATTestHandler{connections: connections},
		func(key udpSessionKey, _ M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.WithValue(context.Background(), udpNATContextKey{}, key), udpNATTestWriter{}, nil
		},
		time.Hour,
	)
	t.Cleanup(func() { _ = service.Close() })

	source := M.ParseSocksaddr("192.0.2.10:53000")
	destination := M.ParseSocksaddr("223.5.5.5:53")
	for cookie := uint64(1); cookie <= 1025; cookie++ {
		service.NewPacket(
			udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalTC, SocketCookie: cookie},
			[][]byte{[]byte("packet")}, source, destination, nil,
		)
	}
	diagnostics := service.diagnostics()
	if diagnostics.ActiveSessions != 1024 || diagnostics.CreatedSessions != 1025 || diagnostics.CapacityEvictions != 1 {
		t.Fatalf("unexpected UDP NAT cache diagnostics: %+v", diagnostics)
	}
}

func TestUDPNATHandlerCanCloseWhileQueuedPacketsDrain(t *testing.T) {
	connections := make(chan udpNATTestConnection, 1)
	service := newUDPNATService(
		&udpNATTestHandler{connections: connections},
		func(key udpSessionKey, _ M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.WithValue(context.Background(), udpNATContextKey{}, key), udpNATTestWriter{}, nil
		},
		time.Minute,
	)
	t.Cleanup(func() { _ = service.Close() })

	source := M.ParseSocksaddr("192.0.2.10:53000")
	destination := M.ParseSocksaddr("1.1.1.1:53")
	key := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalTC}
	buffer := buf.NewPacket()
	_, _ = buffer.WriteString("queued")
	service.NewPacketBuffer(key, buffer, source, destination, nil)
	secondBuffer := buf.NewPacket()
	_, _ = secondBuffer.WriteString("also queued")
	service.NewPacketBuffer(key, secondBuffer, source, destination, nil)
	connection := receiveUDPNATTestConnection(t, connections)
	natConn := connection.conn.(*udpNATConn)
	closingHandler := &udpNATClosingPacketHandler{conn: natConn}

	finished := make(chan struct{})
	go func() {
		natConn.SetHandler(closingHandler)
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(2 * time.Second):
		t.Fatal("UDP handler closing its connection deadlocked queue draining")
	}
	if buffer.Cap() != 0 || secondBuffer.Cap() != 0 {
		t.Fatal("queued packets were not released when their handler closed the connection")
	}
	if closingHandler.calls != 1 {
		t.Fatalf("closing handler received %d packets, want 1", closingHandler.calls)
	}
}

func TestUDPNATExpiresWithoutAnotherPacket(t *testing.T) {
	connections := make(chan udpNATTestConnection, 1)
	service := newUDPNATService(
		&udpNATTestHandler{connections: connections},
		func(key udpSessionKey, _ M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.WithValue(context.Background(), udpNATContextKey{}, key), udpNATTestWriter{}, nil
		},
		30*time.Millisecond,
	)
	t.Cleanup(func() { _ = service.Close() })

	source := M.ParseSocksaddr("192.0.2.10:53000")
	destination := M.ParseSocksaddr("1.1.1.1:53")
	key := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalCgroup, SocketCookie: 42}
	buffer := buf.NewPacket()
	_, _ = buffer.WriteString("queued")
	service.NewPacketBuffer(key, buffer, source, destination, nil)
	connection := receiveUDPNATTestConnection(t, connections)
	natConn := connection.conn.(*udpNATConn)

	select {
	case <-natConn.doneChan:
	case <-time.After(2 * time.Second):
		t.Fatal("UDP NAT connection did not expire without another packet")
	}
	if buffer.Cap() != 0 {
		t.Fatal("queued packet was not released when the UDP NAT connection expired")
	}
	if _, loaded := service.cache.Peek(key); loaded {
		t.Fatal("expired UDP NAT connection remains cached")
	}
}

func TestUDPNATRefreshPostponesCleanup(t *testing.T) {
	connections := make(chan udpNATTestConnection, 1)
	service := newUDPNATService(
		&udpNATTestHandler{connections: connections},
		func(key udpSessionKey, _ M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.WithValue(context.Background(), udpNATContextKey{}, key), udpNATTestWriter{}, nil
		},
		200*time.Millisecond,
	)
	t.Cleanup(func() { _ = service.Close() })

	source := M.ParseSocksaddr("192.0.2.10:53000")
	destination := M.ParseSocksaddr("1.1.1.1:53")
	key := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalTC, SocketCookie: 7}
	service.NewPacket(key, [][]byte{[]byte("first")}, source, destination, nil)
	connection := receiveUDPNATTestConnection(t, connections)
	natConn := connection.conn.(*udpNATConn)
	time.Sleep(120 * time.Millisecond)
	service.NewPacket(key, [][]byte{[]byte("refresh")}, source, destination, nil)

	select {
	case <-natConn.doneChan:
		t.Fatal("UDP NAT cleanup ignored the refreshed lifetime")
	case <-time.After(120 * time.Millisecond):
	}
	select {
	case <-natConn.doneChan:
	case <-time.After(2 * time.Second):
		t.Fatal("refreshed UDP NAT connection did not eventually expire")
	}
}

func TestUDPNATSetTimeoutReschedulesCleanup(t *testing.T) {
	connections := make(chan udpNATTestConnection, 1)
	service := newUDPNATService(
		&udpNATTestHandler{connections: connections},
		func(key udpSessionKey, _ M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.WithValue(context.Background(), udpNATContextKey{}, key), udpNATTestWriter{}, nil
		},
		time.Minute,
	)
	t.Cleanup(func() { _ = service.Close() })

	source := M.ParseSocksaddr("192.0.2.10:53000")
	destination := M.ParseSocksaddr("1.1.1.1:53")
	key := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeSharedTC, InterfaceIndex: 12}
	service.NewPacket(key, [][]byte{[]byte("packet")}, source, destination, nil)
	connection := receiveUDPNATTestConnection(t, connections)
	natConn := connection.conn.(*udpNATConn)
	if !natConn.SetTimeout(30 * time.Millisecond) {
		t.Fatal("failed to shorten UDP NAT timeout")
	}

	select {
	case <-natConn.doneChan:
	case <-time.After(2 * time.Second):
		t.Fatal("shortened UDP NAT timeout did not wake cleanup")
	}
}

func TestUDPNATCloseRemovesConnectionImmediately(t *testing.T) {
	connections := make(chan udpNATTestConnection, 1)
	service := newUDPNATService(
		&udpNATTestHandler{connections: connections},
		func(key udpSessionKey, _ M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.WithValue(context.Background(), udpNATContextKey{}, key), udpNATTestWriter{}, nil
		},
		time.Hour,
	)
	t.Cleanup(func() { _ = service.Close() })

	source := M.ParseSocksaddr("192.0.2.10:53000")
	destination := M.ParseSocksaddr("1.1.1.1:53")
	key := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalCgroup, SocketCookie: 99}
	service.NewPacket(key, [][]byte{[]byte("packet")}, source, destination, nil)
	connection := receiveUDPNATTestConnection(t, connections)
	if err := connection.conn.Close(); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, loaded := service.cache.Peek(key); !loaded {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("closed UDP NAT connection remains cached")
		}
		time.Sleep(time.Millisecond)
	}
	if _, loaded := service.cleanup.next(); loaded {
		t.Fatal("closed UDP NAT connection remains scheduled for cleanup")
	}
}

func TestUDPNATSocketReleaseClosesLocalCgroupConnection(t *testing.T) {
	connections := make(chan udpNATTestConnection, 1)
	service := newUDPNATService(
		&udpNATTestHandler{connections: connections},
		func(key udpSessionKey, _ M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.WithValue(context.Background(), udpNATContextKey{}, key), udpNATTestWriter{}, nil
		},
		time.Hour,
	)
	t.Cleanup(func() { _ = service.Close() })

	source := M.ParseSocksaddr("192.0.2.10:53000")
	destination := M.ParseSocksaddr("223.5.5.5:53")
	key := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalCgroup, SocketCookie: 42}
	service.NewPacket(key, [][]byte{[]byte("packet")}, source, destination, nil)
	natConn := receiveUDPNATTestConnection(t, connections).conn.(*udpNATConn)
	service.ReleaseSocket(key.SocketCookie)

	select {
	case <-natConn.doneChan:
	case <-time.After(time.Second):
		t.Fatal("socket-release event did not close local cgroup UDP session")
	}
	diagnostics := service.diagnostics()
	if diagnostics.SocketReleaseEvents != 1 || diagnostics.SocketReleaseMatched != 1 {
		t.Fatalf("unexpected socket-release diagnostics: %+v", diagnostics)
	}
}

func TestUDPNATSocketReleaseBeforeSession(t *testing.T) {
	connections := make(chan udpNATTestConnection, 1)
	service := newUDPNATService(
		&udpNATTestHandler{connections: connections},
		func(key udpSessionKey, _ M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.WithValue(context.Background(), udpNATContextKey{}, key), udpNATTestWriter{}, nil
		},
		time.Hour,
	)
	t.Cleanup(func() { _ = service.Close() })

	source := M.ParseSocksaddr("192.0.2.10:53000")
	destination := M.ParseSocksaddr("223.5.5.5:53")
	key := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalCgroup, SocketCookie: 43}
	service.ReleaseSocket(key.SocketCookie)
	service.NewPacket(key, [][]byte{[]byte("packet")}, source, destination, nil)

	select {
	case <-connections:
		t.Fatal("session handler started after an earlier socket-release event")
	case <-time.After(50 * time.Millisecond):
	}
	if _, loaded := service.cache.Peek(key); loaded {
		t.Fatal("released UDP NAT session remains cached")
	}
	diagnostics := service.diagnostics()
	if diagnostics.SocketReleaseEvents != 1 || diagnostics.SocketReleaseMatched != 0 {
		t.Fatalf("unexpected early socket-release diagnostics: %+v", diagnostics)
	}
}

func TestUDPNATPendingSocketReleaseCapacityIsReported(t *testing.T) {
	service := newUDPNATService(
		&udpNATTestHandler{connections: make(chan udpNATTestConnection, 1)},
		func(udpSessionKey, M.Socksaddr, M.Socksaddr, any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return false, nil, nil, nil
		},
		time.Hour,
	)
	t.Cleanup(func() { _ = service.Close() })

	for cookie := uint64(1); cookie <= udpNATPendingReleaseCapacity+1; cookie++ {
		service.ReleaseSocket(cookie)
	}
	diagnostics := service.diagnostics()
	if diagnostics.SocketReleaseEvents != udpNATPendingReleaseCapacity+1 ||
		diagnostics.PendingReleaseCapacityRejected != 1 {
		t.Fatalf("unexpected pending socket-release diagnostics: %+v", diagnostics)
	}
}

func TestUDPNATSocketReleaseDoesNotCloseTCConnection(t *testing.T) {
	connections := make(chan udpNATTestConnection, 1)
	service := newUDPNATService(
		&udpNATTestHandler{connections: connections},
		func(key udpSessionKey, _ M.Socksaddr, _ M.Socksaddr, _ any) (bool, context.Context, N.PacketWriter, N.CloseHandlerFunc) {
			return true, context.WithValue(context.Background(), udpNATContextKey{}, key), udpNATTestWriter{}, nil
		},
		time.Hour,
	)
	t.Cleanup(func() { _ = service.Close() })

	source := M.ParseSocksaddr("192.0.2.10:53000")
	destination := M.ParseSocksaddr("223.5.5.5:53")
	key := udpSessionKey{Source: source.AddrPort(), Scope: udpSessionScopeLocalTC, SocketCookie: 44}
	service.NewPacket(key, [][]byte{[]byte("packet")}, source, destination, nil)
	natConn := receiveUDPNATTestConnection(t, connections).conn.(*udpNATConn)
	service.ReleaseSocket(key.SocketCookie)

	select {
	case <-natConn.doneChan:
		t.Fatal("cgroup socket-release event closed a local TC UDP session")
	case <-time.After(50 * time.Millisecond):
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
