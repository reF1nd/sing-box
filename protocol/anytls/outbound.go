package anytls

import (
	"context"
	"net"
	"os"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/session"
	"github.com/anytls/sing-anytls/util"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.AnyTLSOutboundOptions](registry, C.TypeAnyTLS, NewOutbound)

	if !strings.Contains(util.Version, "sing-box") {
		util.Version = util.Version + " sing-box/" + C.Version
	}
}

var _ adapter.OutboundWithMultiplex = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	ctx            context.Context
	dialer         tls.Dialer
	server         M.Socksaddr
	tlsConfig      tls.Config
	clientOptions  anytls.ClientConfig
	clientMetadata string
	client         *anytls.Client
	sessionClient  *session.Client
	uotClient      *uot.Client
	logger         log.ContextLogger
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AnyTLSOutboundOptions) (adapter.Outbound, error) {
	outbound := &Outbound{
		Adapter: outbound.NewAdapterWithDialerOptions(C.TypeAnyTLS, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.DialerOptions),
		ctx:     ctx,
		server:  options.ServerOptions.Build(),
		logger:  logger,
	}
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, C.ErrTLSRequired
	}

	tlsConfig, err := tls.NewClient(ctx, logger, options.Server, common.PtrValueOrDefault(options.TLS))
	if err != nil {
		return nil, err
	}
	outbound.tlsConfig = tlsConfig

	outboundDialer, err := dialer.NewWithOptions(dialer.Options{
		Context:        ctx,
		Options:        options.DialerOptions,
		RemoteIsDomain: options.ServerIsDomain(),
	})
	if err != nil {
		return nil, err
	}

	outbound.dialer = tls.NewDialer(outboundDialer, tlsConfig)

	outbound.clientOptions = anytls.ClientConfig{
		Password:                 options.Password,
		IdleSessionCheckInterval: options.IdleSessionCheckInterval.Build(),
		IdleSessionTimeout:       options.IdleSessionTimeout.Build(),
		MinIdleSession:           options.MinIdleSession,
		DisableReuse:             options.DisableReuse,
		DialOut:                  outbound.dialOut,
		Logger:                   logger,
	}
	outbound.clientMetadata = options.ClientMetadata
	return outbound, nil
}

func (h *Outbound) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateInitialize {
		return nil
	}
	client, err := anytls.NewClient(h.ctx, h.clientOptions)
	if err != nil {
		return err
	}
	h.client = client
	h.sessionClient = sessionClientOf(client)
	h.uotClient = &uot.Client{
		Dialer:  anytlsDialer(h.createProxy),
		Version: uot.Version,
	}
	return nil
}

func (h *Outbound) createProxy(ctx context.Context, destination M.Socksaddr) (net.Conn, error) {
	conn, err := h.sessionClient.CreateStream(ctx)
	if err != nil {
		return nil, err
	}
	h.rewriteClientMetadata(conn)
	err = M.SocksaddrSerializer.WriteAddrPort(conn, destination)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

type anytlsDialer func(ctx context.Context, destination M.Socksaddr) (net.Conn, error)

func (d anytlsDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d(ctx, destination)
}

func (d anytlsDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func (h *Outbound) dialOut(ctx context.Context) (net.Conn, error) {
	return h.dialer.DialTLSContext(ctx, h.server)
}

func (h *Outbound) MultiplexEnabled() bool {
	return true
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		return h.createProxy(ctx, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		return h.uotClient.DialContext(ctx, network, destination)
	}
	return nil, os.ErrInvalid
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
	return h.uotClient.ListenPacket(ctx, destination)
}

func (h *Outbound) Close() error {
	return common.Close(common.PtrOrNil(h.client))
}
