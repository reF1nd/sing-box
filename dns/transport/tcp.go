package transport

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

type reusableDNSConn struct {
	net.Conn
	queryId uint16
}

var _ adapter.DNSTransport = (*TCPTransport)(nil)

func RegisterTCP(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteTCPDNSServerOptions](registry, C.DNSTypeTCP, NewTCP)
}

type TCPTransport struct {
	dns.TransportAdapter
	dialer     N.Dialer
	serverAddr M.Socksaddr

	connections *ConnPool[*reusableDNSConn]
}

func NewTCP(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteTCPDNSServerOptions) (adapter.DNSTransport, error) {
	transportDialer, err := dns.NewRemoteDialer(ctx, options.RemoteDNSServerOptions)
	if err != nil {
		return nil, err
	}
	serverAddr := options.DNSServerAddressOptions.Build()
	if serverAddr.Port == 0 {
		serverAddr.Port = 53
	}
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address: ", serverAddr)
	}
	transport := &TCPTransport{
		TransportAdapter: dns.NewTransportAdapterWithRemoteOptions(C.DNSTypeTCP, tag, options.RemoteDNSServerOptions),
		dialer:           transportDialer,
		serverAddr:       serverAddr,
	}
	if options.Reuse {
		transport.connections = NewConnPool(ConnPoolOptions[*reusableDNSConn]{
			Mode: ConnPoolOrdered,
			IsAlive: func(conn *reusableDNSConn) bool {
				return conn != nil
			},
			Close: func(conn *reusableDNSConn, _ error) {
				_ = conn.Close()
			},
		})
	}
	return transport, nil
}

func (t *TCPTransport) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return dialer.InitializeDetour(t.dialer)
}

func (t *TCPTransport) Close() error {
	if t.connections == nil {
		return nil
	}
	return t.connections.Close()
}

func (t *TCPTransport) Reset() {
	if t.connections != nil {
		t.connections.Reset()
	}
}

func (t *TCPTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if t.connections != nil {
		var lastErr error
		for attempt := 0; attempt < 2; attempt++ {
			conn, created, err := t.connections.Acquire(ctx, func(ctx context.Context) (*reusableDNSConn, error) {
				netConn, err := t.dialer.DialContext(ctx, N.NetworkTCP, t.serverAddr)
				if err != nil {
					return nil, E.Cause(err, "dial TCP connection")
				}
				return &reusableDNSConn{Conn: netConn}, nil
			})
			if err != nil {
				return nil, err
			}
			response, err := t.exchange(ctx, message, conn)
			if err == nil {
				t.connections.Release(conn, true)
				return response, nil
			}
			lastErr = err
			t.connections.Release(conn, false)
			if created {
				return nil, err
			}
		}
		return nil, lastErr
	}
	netConn, err := t.dialer.DialContext(ctx, N.NetworkTCP, t.serverAddr)
	if err != nil {
		return nil, E.Cause(err, "dial TCP connection")
	}
	response, err := t.exchange(ctx, message, &reusableDNSConn{Conn: netConn})
	_ = netConn.Close()
	return response, err
}

func (t *TCPTransport) exchange(ctx context.Context, message *mDNS.Msg, conn *reusableDNSConn) (*mDNS.Msg, error) {
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	}
	conn.queryId++
	err := WriteMessage(conn, conn.queryId, message)
	if err != nil {
		return nil, E.Cause(err, "write request")
	}
	response, err := ReadMessage(conn)
	if err != nil {
		return nil, E.Cause(err, "read response")
	}
	conn.SetDeadline(time.Time{})
	return response, nil
}

func ReadMessage(reader io.Reader) (*mDNS.Msg, error) {
	var responseLen uint16
	err := binary.Read(reader, binary.BigEndian, &responseLen)
	if err != nil {
		return nil, err
	}
	if responseLen < 10 {
		return nil, mDNS.ErrShortRead
	}
	buffer := buf.NewSize(int(responseLen))
	defer buffer.Release()
	_, err = buffer.ReadFullFrom(reader, int(responseLen))
	if err != nil {
		return nil, err
	}
	var message mDNS.Msg
	err = message.Unpack(buffer.Bytes())
	return &message, err
}

func WriteMessage(writer io.Writer, messageId uint16, message *mDNS.Msg) error {
	requestLen := message.Len()
	buffer := buf.NewSize(3 + requestLen)
	defer buffer.Release()
	common.Must(binary.Write(buffer, binary.BigEndian, uint16(requestLen)))
	exMessage := *message
	exMessage.Id = messageId
	exMessage.Compress = true
	rawMessage, err := exMessage.PackBuffer(buffer.FreeBytes())
	if err != nil {
		return err
	}
	buffer.Truncate(2 + len(rawMessage))
	return common.Error(writer.Write(buffer.Bytes()))
}
