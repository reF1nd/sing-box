package transport

import (
	"context"
	"encoding/binary"
	"io"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/expiringpool"
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

var _ adapter.DNSTransport = (*TCPTransport)(nil)

func RegisterTCP(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteTCPDNSServerOptions](registry, C.DNSTypeTCP, NewTCP)
}

type TCPTransport struct {
	dns.TransportAdapter
	dialer     N.Dialer
	serverAddr M.Socksaddr

	connections *expiringpool.ExpiringPool[*reusableDNSConn]
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
		transport.connections = expiringpool.New(ctx, C.TCPKeepAliveInterval, func(t *reusableDNSConn) {
			_ = t.Close()
		})
	}
	return transport, nil
}

func (t *TCPTransport) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if t.connections != nil {
		t.connections.Start()
	}
	return dialer.InitializeDetour(t.dialer)
}

func (t *TCPTransport) Close() error {
	if t.connections == nil {
		return nil
	}
	t.connections.Close()
	return nil
}

func (t *TCPTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if t.connections != nil {
		conn := t.connections.Get()
		if conn != nil {
			response, err := t.exchange(message, conn)
			if err == nil {
				return response, nil
			}
		}
	}
	conn, err := t.dialer.DialContext(ctx, N.NetworkTCP, t.serverAddr)
	if err != nil {
		return nil, err
	}
	return t.exchange(message, &reusableDNSConn{Conn: conn})
}

func (t *TCPTransport) exchange(message *mDNS.Msg, conn *reusableDNSConn) (*mDNS.Msg, error) {
	conn.queryId++
	err := WriteMessage(conn, conn.queryId, message)
	if err != nil {
		_ = conn.Close()
		return nil, E.Cause(err, "write request")
	}
	response, err := ReadMessage(conn)
	if err != nil {
		_ = conn.Close()
		return nil, E.Cause(err, "read response")
	}
	if t.connections != nil {
		t.connections.Put(conn)
	}
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
