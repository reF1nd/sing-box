package snell

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/log"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/stretchr/testify/require"
)

func TestValidateSnellInboundObfs(t *testing.T) {
	require.NoError(t, validateSnellInboundObfs(5, "http"))
	require.EqualError(t, validateSnellInboundObfs(5, "tls"), "snell: TLS obfs is unsupported for version 5; use ShadowTLS instead")
}

type blockingQUICProxyInitParser struct {
	started chan struct{}
	release chan struct{}
	target  M.Socksaddr
	payload []byte
}

func (p *blockingQUICProxyInitParser) ParseQUICProxyInit([]byte) (*snellprotocol.QUICProxySession, []byte, error) {
	close(p.started)
	<-p.release
	return snellprotocol.NewQUICProxySession([]byte("test-password"), p.target, nil), p.payload, nil
}

func TestQUICProxyAuthenticationDoesNotBlockUDPListener(t *testing.T) {
	natService, handler := newQUICProxyNATTestService(t, time.Minute, 1)
	parser := &blockingQUICProxyInitParser{
		started: make(chan struct{}),
		release: make(chan struct{}),
		target:  M.ParseSocksaddr("example.com:443"),
		payload: []byte{0xc0, 0, 0, 0, 1, 1},
	}
	inbound := &Inbound{
		ctx:    context.Background(),
		logger: log.NewNOPFactory().NewLogger("snell"),
		udpNat: natService,
	}
	inbound.quicAuth = newQUICProxyAuthenticationService(parser, natService, inbound.logger)
	t.Cleanup(inbound.quicAuth.Close)
	source := M.ParseSocksaddr("127.0.0.1:10000")
	initPacket := buf.As([]byte{1})
	returned := make(chan struct{})
	go func() {
		(*inboundPacketHandler)(inbound).NewPacket(initPacket, source)
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(time.Second):
		t.Fatal("UDP packet handler blocked on QUIC proxy authentication")
	}
	select {
	case <-parser.started:
	case <-time.After(time.Second):
		t.Fatal("QUIC proxy authentication did not start")
	}

	nextPacket := []byte{0xc0, 0, 0, 0, 1, 2, 3}
	(*inboundPacketHandler)(inbound).NewPacket(buf.As(nextPacket), source)
	close(parser.release)

	var event quicProxyNATTestEvent
	select {
	case event = <-handler.events:
	case <-time.After(time.Second):
		t.Fatal("pending Initial was not delivered after authentication")
	}
	readBuffer := buf.NewSize(len(parser.payload))
	defer readBuffer.Release()
	destination, err := event.conn.ReadPacket(readBuffer)
	require.NoError(t, err)
	require.Equal(t, parser.target, destination)
	require.Equal(t, parser.payload, readBuffer.Bytes())
	nextBuffer := buf.NewSize(len(nextPacket))
	defer nextBuffer.Release()
	destination, err = event.conn.ReadPacket(nextBuffer)
	require.NoError(t, err)
	require.Equal(t, parser.target, destination)
	require.Equal(t, nextPacket, nextBuffer.Bytes())
}

type gatedQUICProxyInitParser struct {
	started atomic.Int32
	release chan struct{}
}

func (p *gatedQUICProxyInitParser) ParseQUICProxyInit([]byte) (*snellprotocol.QUICProxySession, []byte, error) {
	p.started.Add(1)
	<-p.release
	return nil, nil, errors.New("rejected")
}

func TestQUICProxyAuthenticationQueueIsBounded(t *testing.T) {
	natService, _ := newQUICProxyNATTestService(t, time.Minute, 0)
	parser := &gatedQUICProxyInitParser{release: make(chan struct{})}
	service := newQUICProxyAuthenticationService(parser, natService, log.NewNOPFactory().NewLogger("snell"))
	t.Cleanup(func() {
		close(parser.release)
		service.Close()
	})
	for index := range quicProxyAuthenticationWorkers {
		source := M.ParseSocksaddrHostPort("127.0.0.1", uint16(index+1))
		require.True(t, service.Submit(source, []byte{1}))
	}
	require.Eventually(t, func() bool {
		return parser.started.Load() == quicProxyAuthenticationWorkers
	}, time.Second, time.Millisecond)
	for index := range quicProxyAuthenticationQueueSize {
		source := M.ParseSocksaddrHostPort("127.0.0.1", uint16(quicProxyAuthenticationWorkers+index+1))
		require.True(t, service.Submit(source, []byte{1}))
	}
	overflowSource := M.ParseSocksaddrHostPort("127.0.0.1", uint16(quicProxyAuthenticationWorkers+quicProxyAuthenticationQueueSize+1))
	require.False(t, service.Submit(overflowSource, []byte{1}))
}
