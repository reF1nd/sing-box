package transport

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

var _ adapter.DNSTransport = (*TLSTransport)(nil)

func RegisterTLS(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.RemoteTLSDNSServerOptions](registry, C.DNSTypeTLS, NewTLS)
}

type TLSTransport struct {
	dns.TransportAdapter
	dialer     tls.Dialer
	serverAddr M.Socksaddr
	tlsConfig  tls.Config
	pipelinePool
}

func NewTLS(ctx context.Context, logger log.ContextLogger, tag string, options option.RemoteTLSDNSServerOptions) (adapter.DNSTransport, error) {
	transportDialer, err := dns.NewRemoteDialer(ctx, options.RemoteDNSServerOptions)
	if err != nil {
		return nil, err
	}
	tlsOptions := common.PtrValueOrDefault(options.TLS)
	tlsOptions.Enabled = true
	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, tlsOptions)
	if err != nil {
		return nil, err
	}
	serverAddr := options.DNSServerAddressOptions.Build()
	if serverAddr.Port == 0 {
		serverAddr.Port = 853
	}
	if !serverAddr.IsValid() {
		return nil, E.New("invalid server address: ", serverAddr)
	}
	var poolIdleTimeout time.Duration
	if options.DisableTCPKeepAlive {
		poolIdleTimeout = 2 * time.Minute
	} else {
		var keepAliveIdle, keepAliveInterval time.Duration
		if options.TCPKeepAlive != 0 {
			keepAliveIdle = time.Duration(options.TCPKeepAlive)
		} else {
			keepAliveIdle = C.TCPKeepAliveInitial
		}
		if options.TCPKeepAliveInterval != 0 {
			keepAliveInterval = time.Duration(options.TCPKeepAliveInterval)
		} else {
			keepAliveInterval = C.TCPKeepAliveInterval
		}
		poolIdleTimeout = keepAliveIdle + keepAliveInterval
	}
	maxQueries := options.MaxQueries
	if maxQueries <= 0 {
		maxQueries = 0
	}
	if !options.Pipeline && maxQueries > 0 {
		maxQueries = 0
	}
	return NewTLSRaw(ctx, logger, dns.NewTransportAdapterWithRemoteOptions(C.DNSTypeTLS, tag, options.RemoteDNSServerOptions), transportDialer, serverAddr, tlsConfig, options.Pipeline, poolIdleTimeout, options.DisableTCPKeepAlive, maxQueries), nil
}

func NewTLSRaw(_ context.Context, logger logger.ContextLogger, adapter dns.TransportAdapter, dialer N.Dialer, serverAddr M.Socksaddr, tlsConfig tls.Config, enablePipeline bool, idleTimeout time.Duration, disableKeepAlive bool, maxQueries int) *TLSTransport {
	return &TLSTransport{
		TransportAdapter: adapter,
		dialer:           tls.NewDialer(dialer, tlsConfig),
		serverAddr:       serverAddr,
		tlsConfig:        tlsConfig,
		pipelinePool: pipelinePool{
			logger:           logger,
			enablePipeline:   enablePipeline,
			idleTimeout:      idleTimeout,
			disableKeepAlive: disableKeepAlive,
			maxQueries:       maxQueries,
			connections:      newReuseableDNSConnPool(),
		},
	}
}

func (t *TLSTransport) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	return dialer.InitializeDetour(t.dialer)
}

func (t *TLSTransport) Close() error {
	return t.pipelinePool.closePool()
}

func (t *TLSTransport) Reset() {
	t.pipelinePool.resetPool()
}

func (t *TLSTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	return t.pipelinePool.exchange(ctx, message, t.createNewConnection)
}

func (t *TLSTransport) createNewConnection(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	conn, _, err := t.connections.Acquire(ctx, func(ctx context.Context) (*reuseableDNSConn, error) {
		tlsConn, err := t.dialer.DialTLSContext(ctx, t.serverAddr)
		if err != nil {
			return nil, E.Cause(err, "dial TLS connection")
		}
		var connIdleTimeout time.Duration
		if t.disableKeepAlive {
			connIdleTimeout = t.idleTimeout
		}
		return newReuseableDNSConn(tlsConn, t.logger, t.enablePipeline, connIdleTimeout, t.maxQueries, t.connections, t), nil
	})
	if err != nil {
		return nil, err
	}
	if t.enablePipeline && t.maxQueries > 0 {
		t.addActiveConn(conn)
	}
	return conn.Exchange(ctx, message)
}
