package snell

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing/common/auth"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestValidateSnellInboundObfs(t *testing.T) {
	require.NoError(t, validateSnellInboundObfs(5, "http"))
	require.EqualError(t, validateSnellInboundObfs(5, "tls"), "snell: TLS obfs is unsupported for version 5; use ShadowTLS instead")
}

func TestV6InboundEnablesQUICProxyCompatibility(t *testing.T) {
	for _, testCase := range []struct {
		name          string
		options       option.AbstractSnellInboundOptions
		clientPSK     []byte
		clientUserKey []byte
		expectedUser  int
		hasUser       bool
	}{
		{
			name:      "single-user",
			options:   option.AbstractSnellInboundOptions{PSK: "test-password"},
			clientPSK: []byte("test-password"),
		},
		{
			name: "userkey",
			options: option.AbstractSnellInboundOptions{
				PSK:                     "test-password",
				Users:                   []option.SnellUser{{Name: "alice", UserKey: "alice-key"}},
				MultiUserAuthentication: "userkey",
			},
			clientPSK:     []byte("test-password"),
			clientUserKey: []byte("alice-key"),
			expectedUser:  0,
			hasUser:       true,
		},
		{
			name: "psk",
			options: option.AbstractSnellInboundOptions{
				Users:                   []option.SnellUser{{Name: "alice", PSK: "alice-password"}},
				MultiUserAuthentication: "psk",
			},
			clientPSK:     []byte("alice-password"),
			clientUserKey: []byte("surge-client"),
			expectedUser:  0,
			hasUser:       true,
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			created, err := NewInbound(
				context.Background(),
				nil,
				log.NewNOPFactory().NewLogger("snell"),
				"snell-in",
				option.SnellInboundOptions{
					Version:                     6,
					AbstractSnellInboundOptions: testCase.options,
				},
			)
			require.NoError(t, err)
			inbound := created.(*Inbound)
			t.Cleanup(func() { require.NoError(t, inbound.Close()) })
			require.NotNil(t, inbound.udpNat)
			require.NotNil(t, inbound.quicAuth)

			target := M.ParseSocksaddr("example.com:443")
			payload := []byte{0xc0, 0, 0, 0, 1, 1}
			serverConn := new(captureQUICProxyWritesConn)
			_, err = snellprotocol.NewQUICProxyPacketConn(serverConn, testCase.clientPSK, testCase.clientUserKey, target, payload)
			require.NoError(t, err)
			require.Len(t, serverConn.writes, 1)
			session, decodedPayload, err := inbound.quicAuth.parser.ParseQUICProxyInit(serverConn.writes[0])
			require.NoError(t, err)
			require.Equal(t, target, session.Target())
			require.Equal(t, payload, decodedPayload)
			user, loaded := auth.UserFromContext[int](session.Context(context.Background()))
			require.Equal(t, testCase.hasUser, loaded)
			if testCase.hasUser {
				require.Equal(t, testCase.expectedUser, user)
			}
		})
	}
}

func TestSnellInboundStartsQUICProxyListener(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		version int
	}{
		{"v5", 5},
		{"v6", 6},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			created, err := NewInbound(
				context.Background(),
				nil,
				log.NewNOPFactory().NewLogger("snell"),
				"snell-in",
				option.SnellInboundOptions{
					Version: testCase.version,
					AbstractSnellInboundOptions: option.AbstractSnellInboundOptions{
						PSK: "test-password",
					},
				},
			)
			require.NoError(t, err)
			inbound := created.(*Inbound)
			t.Cleanup(func() { require.NoError(t, inbound.Close()) })
			require.NoError(t, inbound.Start(adapter.StartStateStart))
			require.NotNil(t, inbound.listener.TCPListener())
			require.NotNil(t, inbound.listener.UDPConn())
		})
	}
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
