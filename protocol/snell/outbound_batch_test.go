package snell

import (
	"context"
	"io"
	"net"
	"os"
	"testing"
	"time"

	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/stretchr/testify/require"
)

type lazyBatchTestClient struct {
	lazyPacketTestClient
	conn N.NetPacketConn
}

func (c *lazyBatchTestClient) DialPacketConn(net.Conn) (N.NetPacketConn, error) { return c.conn, nil }

type lazyBatchTestConn struct {
	N.NetPacketConn
	payloads     [][]byte
	destinations []M.Socksaddr
	batches      []int
	fail         bool
}

func (c *lazyBatchTestConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	c.payloads = append(c.payloads, append([]byte(nil), p...))
	c.destinations = append(c.destinations, M.SocksaddrFromNet(addr))
	return len(p), nil
}

func (c *lazyBatchTestConn) WritePacketBatch(buffers []*buf.Buffer, destinations []M.Socksaddr) error {
	defer buf.ReleaseMulti(buffers)
	c.batches = append(c.batches, len(buffers))
	if c.fail {
		return io.ErrClosedPipe
	}
	for i, buffer := range buffers {
		if buffer.Start() < c.FrontHeadroom() || buffer.FreeLen() < c.RearHeadroom() {
			return io.ErrShortBuffer
		}
		c.WriteTo(buffer.Bytes(), destinations[i])
	}
	return nil
}

func (*lazyBatchTestConn) FrontHeadroom() int { return 32 }

func (*lazyBatchTestConn) RearHeadroom() int { return 16 }

func (*lazyBatchTestConn) Close() error { return nil }

func lazyBatchBuffers(payloads ...[]byte) []*buf.Buffer {
	buffers := make([]*buf.Buffer, len(payloads))
	for i, payload := range payloads {
		buffers[i] = buf.NewSize(len(payload))
		buffers[i].Write(payload)
	}
	return buffers
}

func TestQUICProxyLazyPacketBatchUDP(t *testing.T) {
	upstream := new(lazyBatchTestConn)
	outbound := &Outbound{tcpDialer: &lazyPacketTestDialer{conn: new(captureQUICProxyWritesConn)}, client: &lazyBatchTestClient{conn: upstream}}
	destination := M.ParseSocksaddr("192.0.2.1:443")
	conn := newQUICProxyLazyPacketConn(context.Background(), outbound, M.Socksaddr{}, destination, false)
	t.Cleanup(func() { conn.Close() })
	writer, created := bufio.CreatePacketBatchWriter(conn)
	require.True(t, created)
	select {
	case <-conn.initDone:
		t.Fatal("creating a writer initialized the connection")
	default:
	}
	destinations := []M.Socksaddr{destination, M.ParseSocksaddr("[2001:db8::1]:53"), M.ParseSocksaddr("example.com:123")}
	payloads := [][]byte{{1, 2}, {3, 4}, {5, 6}}
	require.NoError(t, writer.WritePacketBatch(lazyBatchBuffers(payloads...), destinations))
	require.Equal(t, payloads, upstream.payloads)
	require.Equal(t, destinations, upstream.destinations)
	require.Equal(t, []int{2}, upstream.batches, "only the first packet should use lazy initialization")
	require.NoError(t, writer.WritePacketBatch(lazyBatchBuffers(payloads...), destinations))
	require.Equal(t, []int{2, 3}, upstream.batches)
	upstream.fail = true
	buffers := lazyBatchBuffers(payloads...)
	require.ErrorIs(t, writer.WritePacketBatch(buffers, destinations), io.ErrClosedPipe)
	for _, buffer := range buffers {
		require.Zero(t, buffer.Cap())
	}
	require.Len(t, upstream.payloads, 6)
}

func TestQUICProxyLazyPacketBatchInitPayload(t *testing.T) {
	for _, sniffed := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "sniffed"}[sniffed], func(t *testing.T) {
			psk := []byte("test-password")
			upstream := new(captureQUICProxyWritesConn)
			destination := M.ParseSocksaddr("example.com:443")
			outbound := &Outbound{dialer: &lazyPacketTestDialer{conn: upstream}, psk: psk, userKey: []byte("alice")}
			conn := newQUICProxyLazyPacketConn(context.Background(), outbound, M.Socksaddr{}, destination, sniffed)
			t.Cleanup(func() { conn.Close() })
			writer, created := bufio.CreatePacketBatchWriter(conn)
			require.True(t, created)
			require.NoError(t, writer.WritePacketBatch(lazyBatchBuffers(nil, nil), []M.Socksaddr{destination, destination}))
			require.Empty(t, upstream.writes)
			select {
			case <-conn.initDone:
				t.Fatal("empty packets consumed initialization")
			default:
			}
			first := []byte{0xc0, 0, 0, 0, 1, 1, 2, 3}
			if sniffed {
				first = []byte{0x40, 1, 2, 3}
			}
			require.NoError(t, writer.WritePacketBatch(lazyBatchBuffers(nil, first, []byte{0x40, 4, 5}), []M.Socksaddr{destination, destination, destination}))
			require.Len(t, upstream.writes, 2, "first payload must be included only in the init frame")
			target, key, payload, err := snellprotocol.DecodeQUICProxyInit(psk, upstream.writes[0])
			require.NoError(t, err)
			require.Equal(t, destination, target)
			require.Equal(t, []byte("alice"), key)
			require.Equal(t, first, payload)
		})
	}
}

func TestQUICProxyLazyPacketBatchErrors(t *testing.T) {
	for _, kind := range []string{"empty", "mismatch", "closed", "deadline"} {
		t.Run(kind, func(t *testing.T) {
			conn := newQUICProxyLazyPacketConn(context.Background(), nil, M.Socksaddr{}, M.Socksaddr{}, false)
			t.Cleanup(func() { conn.Close() })
			writer, created := bufio.CreatePacketBatchWriter(conn)
			require.True(t, created)
			buffers := lazyBatchBuffers([]byte{1}, []byte{2})
			destinations := make([]M.Socksaddr, 2)
			want := error(os.ErrInvalid)
			switch kind {
			case "empty":
				buf.ReleaseMulti(buffers)
				buffers = nil
				destinations = nil
			case "mismatch":
				destinations = destinations[:1]
			case "closed":
				require.NoError(t, conn.Close())
				want = net.ErrClosed
			case "deadline":
				require.NoError(t, conn.SetWriteDeadline(time.Now().Add(-time.Second)))
				want = os.ErrDeadlineExceeded
			}
			require.ErrorIs(t, writer.WritePacketBatch(buffers, destinations), want)
			for _, buffer := range buffers {
				require.Zero(t, buffer.Cap(), "rejected buffers must be released")
			}
			select {
			case <-conn.initDone:
				t.Fatal("rejected batch initialized the connection")
			default:
			}
		})
	}
}

type lazyBatchSource struct {
	reads       int
	destination M.Socksaddr
}

func (*lazyBatchSource) InitializeReadWaiter(N.ReadWaitOptions) bool {
	return false
}

func (*lazyBatchSource) ReadPacket(*buf.Buffer) (M.Socksaddr, error) {
	return M.Socksaddr{}, io.ErrUnexpectedEOF
}

func (s *lazyBatchSource) WaitReadPackets() ([]*buf.Buffer, []M.Socksaddr, error) {
	s.reads++
	if s.reads > 1 {
		return nil, nil, io.EOF
	}
	return lazyBatchBuffers([]byte{1}, []byte{2}), []M.Socksaddr{s.destination, s.destination}, nil
}

func TestQUICProxyLazyPacketBatchCopy(t *testing.T) {
	upstream := new(lazyBatchTestConn)
	outbound := &Outbound{tcpDialer: &lazyPacketTestDialer{conn: new(captureQUICProxyWritesConn)}, client: &lazyBatchTestClient{conn: upstream}}
	destination := M.ParseSocksaddr("192.0.2.1:443")
	conn := newQUICProxyLazyPacketConn(context.Background(), outbound, M.Socksaddr{}, destination, false)
	t.Cleanup(func() { conn.Close() })
	_, created := bufio.CreatePacketBatchWriter(conn)
	require.True(t, created)
	source := &lazyBatchSource{destination: destination}
	n, err := bufio.CopyPacket(conn, source)
	require.ErrorIs(t, err, io.EOF)
	require.EqualValues(t, 2, n)
	require.Equal(t, 2, source.reads)
	require.Equal(t, []int{1}, upstream.batches)
}

func TestQUICProxyLazyPacketBatchInterruptInit(t *testing.T) {
	for _, closeConnection := range []bool{false, true} {
		name := "deadline"
		if closeConnection {
			name = "close"
		}
		t.Run(name, func(t *testing.T) {
			clientConn, serverConn := net.Pipe()
			t.Cleanup(func() { serverConn.Close() })
			client := &lazyPacketTestClient{writeStarted: make(chan struct{})}
			outbound := &Outbound{tcpDialer: &lazyPacketTestDialer{conn: clientConn}, client: client}
			conn := newQUICProxyLazyPacketConn(context.Background(), outbound, M.Socksaddr{}, M.Socksaddr{}, false)
			t.Cleanup(func() { conn.Close() })
			writer, created := bufio.CreatePacketBatchWriter(conn)
			require.True(t, created)
			buffers := lazyBatchBuffers([]byte{1}, []byte{2})
			done := make(chan error, 1)
			go func() { done <- writer.WritePacketBatch(buffers, make([]M.Socksaddr, 2)) }()
			select {
			case <-client.writeStarted:
			case <-time.After(time.Second):
				t.Fatal("batch did not start lazy initialization")
			}
			var expected error = os.ErrDeadlineExceeded
			if closeConnection {
				expected = net.ErrClosed
				require.NoError(t, conn.Close())
			} else {
				require.NoError(t, conn.SetWriteDeadline(time.Now().Add(20*time.Millisecond)))
			}
			select {
			case err := <-done:
				require.ErrorIs(t, err, expected)
			case <-time.After(time.Second):
				t.Fatal("batch ignored initialization interruption")
			}
			for _, buffer := range buffers {
				require.Zero(t, buffer.Cap())
			}
		})
	}
}
