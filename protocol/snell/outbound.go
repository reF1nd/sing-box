package snell

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/expiringmap"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	obfs "github.com/sagernet/sing-box/transport/simple-obfs"
	snellprotocol "github.com/sagernet/sing-snell"
	"github.com/sagernet/sing-snell/legacy"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing-snell/snellv6"
	"github.com/sagernet/sing/common/buf"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/pipe"
)

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[option.SnellOutboundOptions](registry, C.TypeSnell, NewOutbound)
}

type Outbound struct {
	outbound.Adapter
	logger        logger.ContextLogger
	dialer        N.Dialer
	tcpDialer     N.Dialer
	client        snellClient
	legacy        *legacy.Client
	serverAddr    M.Socksaddr
	psk           []byte
	userKey       []byte
	version       int
	quicDestCache *expiringmap.Map[quicDestCacheKey, uint64]
	quicDestSeq   atomic.Uint64
}

type snellClient interface {
	snellprotocol.Method
	DialContext(ctx context.Context, destination M.Socksaddr) (net.Conn, error)
	Close() error
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SnellOutboundOptions) (adapter.Outbound, error) {
	if options.PSK == "" {
		return nil, E.New("snell: psk is required")
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	serverAddr := options.ServerOptions.Build()
	version := options.Version
	if version == 0 {
		version = 4
	}
	if version == 6 && (len(options.PSK) < 12 || len(options.PSK) > 255) {
		return nil, E.New("snell: psk length must be between 12 and 255 bytes")
	}
	if err = validateSnellOutboundVersionOptions(version, options.Reuse); err != nil {
		return nil, err
	}
	obfsMode := options.ObfsOptions.ObfsMode
	if err = validateSnellOutboundObfs(version, obfsMode); err != nil {
		return nil, err
	}
	networks, err := buildSnellNetworks(version, options.Network)
	if err != nil {
		return nil, err
	}
	tcpDialer := N.Dialer(outboundDialer)
	if obfsMode != "" && obfsMode != "none" {
		tcpDialer = &simpleObfsDialer{
			Dialer: outboundDialer,
			mode:   obfsMode,
			host:   options.ObfsOptions.ObfsHost,
			port:   fmt.Sprint(serverAddr.Port),
		}
	}
	var client snellClient
	var legacyClient *legacy.Client
	switch version {
	case 1, 2, 3:
		legacyClient, err = legacy.NewClient([]byte(options.PSK), version)
	case 4, 5:
		client, err = snellv4.NewClient(snellv4.ClientOptions{
			PSK:     []byte(options.PSK),
			UserKey: []byte(options.UserKey),
			Reuse:   options.Reuse,
			Dialer:  tcpDialer,
			Server:  serverAddr,
		})
	case 6:
		var mode snellv6.Mode
		mode, err = snellv6.ParseMode(options.V6Options.Mode)
		if err != nil {
			return nil, err
		}
		client, err = snellv6.NewClient(snellv6.ClientOptions{
			PSK:     []byte(options.PSK),
			UserKey: []byte(options.UserKey),
			Mode:    mode,
			Reuse:   options.Reuse,
			Dialer:  tcpDialer,
			Server:  serverAddr,
		})
	default:
		return nil, E.New("snell: unsupported version: ", version)
	}
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:    outbound.NewAdapterWithDialerOptions(C.TypeSnell, tag, networks, options.DialerOptions),
		logger:     logger,
		dialer:     outboundDialer,
		tcpDialer:  tcpDialer,
		client:     client,
		legacy:     legacyClient,
		serverAddr: serverAddr,
		psk:        []byte(options.PSK),
		userKey:    []byte(options.UserKey),
		version:    version,
	}
	if version == 5 {
		outbound.quicDestCache = expiringmap.New[quicDestCacheKey, uint64](quicDestCacheTTL)
	}
	return outbound, nil
}

func validateSnellOutboundVersionOptions(version int, reuse bool) error {
	if reuse && version <= 3 {
		return E.New("snell: reuse requires version 4 or above")
	}
	return nil
}

func validateSnellOutboundObfs(version int, obfsMode string) error {
	switch {
	case version <= 3 && (obfsMode == "" || obfsMode == "none" || obfsMode == "http" || obfsMode == "tls"):
	case version <= 5 && (obfsMode == "" || obfsMode == "none" || obfsMode == "http"):
	case version == 6 && obfsMode == "":
	case (version == 4 || version == 5) && obfsMode == "tls":
		return E.New("snell: TLS obfs is unsupported for version ", version, "; use ShadowTLS instead")
	default:
		return E.New("snell: unsupported obfs mode for version ", version, ": ", obfsMode)
	}
	return nil
}

func buildSnellNetworks(version int, networkList option.NetworkList) ([]string, error) {
	networks := []string{N.NetworkTCP}
	if string(networkList) != "" {
		networks = networkList.Build()
	} else if version >= 3 {
		networks = []string{N.NetworkTCP, N.NetworkUDP}
	}
	for _, network := range networks {
		if network == N.NetworkUDP && version < 3 {
			return nil, E.New("snell: UDP requires version 3 or above")
		}
	}
	return networks, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	networkName := N.NetworkName(network)
	switch networkName {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
		if h.legacy != nil {
			conn, err := h.tcpDialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
			if err != nil {
				return nil, err
			}
			return h.legacy.DialContext(ctx, conn, destination), nil
		}
		return h.client.DialContext(ctx, destination)
	case N.NetworkUDP:
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		if h.version == 5 {
			packetConn := newV5LazyPacketConn(ctx, h, metadata.Source, destination, metadata.Protocol == C.ProtocolQUIC || h.isRecentQUICDest(metadata.Source, destination))
			return &packetConnWrapper{PacketConn: packetConn, destination: destination}, nil
		}
		packetConn, err := h.dialUDPOverTCP(ctx)
		if err != nil {
			return nil, err
		}
		return &packetConnWrapper{PacketConn: packetConn, destination: destination}, nil
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	if h.version == 5 {
		return newV5LazyPacketConn(ctx, h, metadata.Source, destination, metadata.Protocol == C.ProtocolQUIC || h.isRecentQUICDest(metadata.Source, destination)), nil
	}
	return h.dialUDPOverTCP(ctx)
}

func (h *Outbound) Close() error {
	if h.quicDestCache != nil {
		h.quicDestCache.Close()
	}
	if h.client == nil {
		return nil
	}
	return h.client.Close()
}

type simpleObfsDialer struct {
	N.Dialer
	mode string
	host string
	port string
}

func (d *simpleObfsDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := d.Dialer.DialContext(ctx, network, destination)
	if err != nil || N.NetworkName(network) != N.NetworkTCP {
		return conn, err
	}
	host := d.host
	if host == "" {
		host = "bing.com"
	}
	if d.mode == "tls" {
		return obfs.NewTLSObfs(conn, host), nil
	}
	return obfs.NewHTTPObfs(conn, host, d.port), nil
}

func (h *Outbound) dialUDPOverTCP(ctx context.Context) (net.PacketConn, error) {
	conn, err := h.tcpDialer.DialContext(ctx, N.NetworkTCP, h.serverAddr)
	if err != nil {
		return nil, err
	}
	var packetConn net.PacketConn
	if h.legacy != nil {
		packetConn, err = h.legacy.DialPacketConn(conn)
	} else {
		packetConn, err = h.client.DialPacketConn(conn)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return packetConn, nil
}

const quicDestCacheTTL = 5 * time.Minute

type quicDestCacheKey struct {
	source      M.Socksaddr
	destination M.Socksaddr
}

func (h *Outbound) isRecentQUICDest(source M.Socksaddr, destination M.Socksaddr) bool {
	if h.quicDestCache == nil {
		return false
	}
	_, loaded := h.quicDestCache.LoadAndRefresh(quicDestCacheKey{source: source, destination: destination})
	return loaded
}

func (h *Outbound) markQUICDest(source M.Socksaddr, destination M.Socksaddr) uint64 {
	if h.quicDestCache == nil {
		return 0
	}
	token := h.quicDestSeq.Add(1)
	if token == 0 {
		token = h.quicDestSeq.Add(1)
	}
	h.quicDestCache.Store(quicDestCacheKey{source: source, destination: destination}, token)
	return token
}

func (h *Outbound) refreshQUICDest(source M.Socksaddr, destination M.Socksaddr, token uint64) {
	if h.quicDestCache == nil || token == 0 {
		return
	}
	h.quicDestCache.StoreIf(quicDestCacheKey{source: source, destination: destination}, token, func(current uint64, loaded bool) bool {
		return !loaded || current == token
	})
}

type v5LazyPacketConn struct {
	outbound    *Outbound
	ctx         context.Context
	cancel      context.CancelFunc
	source      M.Socksaddr
	destination M.Socksaddr
	sniffQUIC   bool

	once           sync.Once
	initDone       chan struct{}
	conn           net.PacketConn
	connErr        error
	initialSent    bool
	quicDestToken  uint64
	closeRequested atomic.Bool
	closed         chan struct{}
	closedOnce     sync.Once
	closeOnce      sync.Once
	deadlineAccess sync.Mutex
	initializing   net.Conn
	readDeadline   time.Time
	writeDeadline  time.Time
	readTimer      pipe.Deadline
	writeTimer     pipe.Deadline
}

func newV5LazyPacketConn(ctx context.Context, outbound *Outbound, source M.Socksaddr, destination M.Socksaddr, sniffQUIC bool) *v5LazyPacketConn {
	initCtx := context.WithoutCancel(ctx)
	var cancel context.CancelFunc
	if deadline, loaded := ctx.Deadline(); loaded {
		initCtx, cancel = context.WithDeadline(initCtx, deadline)
	} else {
		initCtx, cancel = context.WithCancel(initCtx)
	}
	return &v5LazyPacketConn{
		outbound: outbound, ctx: initCtx, cancel: cancel,
		source: source, destination: destination, sniffQUIC: sniffQUIC,
		initDone: make(chan struct{}), closed: make(chan struct{}),
		readTimer: pipe.MakeDeadline(), writeTimer: pipe.MakeDeadline(),
	}
}

func (c *v5LazyPacketConn) initialize(payload []byte) {
	initCtx, initCancel := context.WithCancel(c.ctx)
	deadlineMonitorDone := make(chan struct{})
	var writeDeadlineExceeded atomic.Bool
	go func() {
		select {
		case <-c.writeTimer.Wait():
			writeDeadlineExceeded.Store(true)
			initCancel()
		case <-deadlineMonitorDone:
		}
	}()
	defer func() {
		close(deadlineMonitorDone)
		initCancel()
		c.cancel()
	}()
	useQUIC := c.sniffQUIC || snellprotocol.IsQUICInitial(payload)
	if useQUIC {
		c.conn, c.connErr = c.dialQUICProxy(initCtx, payload)
		c.initialSent = c.connErr == nil
		if c.connErr == nil && c.outbound != nil {
			c.quicDestToken = c.outbound.markQUICDest(c.source, c.destination)
		}
	} else {
		c.conn, c.connErr = c.dialUDPOverTCP(initCtx)
	}
	if c.connErr != nil && writeDeadlineExceeded.Load() {
		c.connErr = os.ErrDeadlineExceeded
	}
	c.deadlineAccess.Lock()
	c.initializing = nil
	if c.conn != nil {
		if !c.readDeadline.IsZero() {
			_ = c.conn.SetReadDeadline(c.readDeadline)
		}
		if !c.writeDeadline.IsZero() {
			_ = c.conn.SetWriteDeadline(c.writeDeadline)
		}
	}
	close(c.initDone)
	c.deadlineAccess.Unlock()
	if c.closeRequested.Load() {
		c.closeOnce.Do(func() {
			if c.conn != nil {
				_ = c.conn.Close()
			}
		})
		c.refreshQUICDestOnClose()
	}
}

func (c *v5LazyPacketConn) registerInitializingConn(conn net.Conn) error {
	c.deadlineAccess.Lock()
	defer c.deadlineAccess.Unlock()
	select {
	case <-c.closed:
		return net.ErrClosed
	default:
	}
	c.initializing = conn
	if c.writeDeadline.IsZero() {
		return nil
	}
	return conn.SetWriteDeadline(c.writeDeadline)
}

func (c *v5LazyPacketConn) dialQUICProxy(ctx context.Context, initialPayload []byte) (net.PacketConn, error) {
	conn, err := c.outbound.dialer.DialContext(ctx, N.NetworkUDP, c.outbound.serverAddr)
	if err != nil {
		return nil, err
	}
	if err = c.registerInitializingConn(conn); err != nil {
		conn.Close()
		return nil, err
	}
	packetConn, err := snellprotocol.NewQUICProxyPacketConn(conn, c.outbound.psk, c.outbound.userKey, c.destination, initialPayload)
	if err != nil {
		conn.Close()
		return nil, err
	}
	return packetConn, nil
}

func (c *v5LazyPacketConn) dialUDPOverTCP(ctx context.Context) (net.PacketConn, error) {
	conn, err := c.outbound.tcpDialer.DialContext(ctx, N.NetworkTCP, c.outbound.serverAddr)
	if err != nil {
		return nil, err
	}
	if err = c.registerInitializingConn(conn); err != nil {
		conn.Close()
		return nil, err
	}
	var packetConn net.PacketConn
	if c.outbound.legacy != nil {
		packetConn, err = c.outbound.legacy.DialPacketConn(conn)
	} else {
		packetConn, err = c.outbound.client.DialPacketConn(conn)
	}
	if err != nil {
		conn.Close()
		return nil, err
	}
	return packetConn, nil
}

func (c *v5LazyPacketConn) WriteTo(payload []byte, destination net.Addr) (int, error) {
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	select {
	case <-c.writeTimer.Wait():
		return 0, os.ErrDeadlineExceeded
	default:
	}
	if len(payload) == 0 {
		select {
		case <-c.initDone:
			if c.connErr != nil {
				return 0, c.connErr
			}
			return c.conn.WriteTo(payload, destination)
		default:
			return 0, nil
		}
	}
	initialized := false
	c.once.Do(func() {
		initialized = true
		c.initialize(payload)
	})
	<-c.initDone
	select {
	case <-c.closed:
		return 0, net.ErrClosed
	default:
	}
	if c.connErr != nil {
		return 0, c.connErr
	}
	if initialized && c.initialSent {
		return len(payload), nil
	}
	return c.conn.WriteTo(payload, destination)
}

func (c *v5LazyPacketConn) ReadFrom(payload []byte) (int, net.Addr, error) {
	conn, err := c.readConn()
	if err != nil {
		return 0, nil, err
	}
	return conn.ReadFrom(payload)
}

func (c *v5LazyPacketConn) readConn() (net.PacketConn, error) {
	select {
	case <-c.closed:
		return nil, net.ErrClosed
	default:
	}
	select {
	case <-c.initDone:
	case <-c.closed:
		return nil, net.ErrClosed
	case <-c.readTimer.Wait():
		return nil, os.ErrDeadlineExceeded
	}
	select {
	case <-c.closed:
		return nil, net.ErrClosed
	default:
	}
	if c.connErr != nil {
		return nil, c.connErr
	}
	return c.conn, nil
}

func (c *v5LazyPacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	conn, err := c.readConn()
	if err != nil {
		return M.Socksaddr{}, err
	}
	if packetReader, loaded := conn.(N.PacketReader); loaded {
		return packetReader.ReadPacket(buffer)
	}
	n, source, err := conn.ReadFrom(buffer.FreeBytes())
	if err != nil {
		return M.Socksaddr{}, err
	}
	buffer.Truncate(n)
	return M.SocksaddrFromNet(source).Unwrap(), nil
}

func (c *v5LazyPacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	defer buffer.Release()
	_, err := c.WriteTo(buffer.Bytes(), destination)
	return err
}

func (c *v5LazyPacketConn) Close() error {
	c.closeRequested.Store(true)
	c.closedOnce.Do(func() {
		close(c.closed)
	})
	c.cancel()
	c.deadlineAccess.Lock()
	initializing := c.initializing
	c.deadlineAccess.Unlock()
	if initializing != nil {
		_ = initializing.Close()
	}
	select {
	case <-c.initDone:
		var closeErr error
		c.closeOnce.Do(func() {
			if c.conn != nil {
				closeErr = c.conn.Close()
			}
		})
		c.refreshQUICDestOnClose()
		return closeErr
	default:
		return nil
	}
}

func (c *v5LazyPacketConn) refreshQUICDestOnClose() {
	if c.outbound != nil {
		c.outbound.refreshQUICDest(c.source, c.destination, c.quicDestToken)
	}
}

func (c *v5LazyPacketConn) LocalAddr() net.Addr {
	select {
	case <-c.initDone:
		if c.conn != nil {
			return c.conn.LocalAddr()
		}
	default:
	}
	return &net.UDPAddr{}
}

func (c *v5LazyPacketConn) SetDeadline(deadline time.Time) error {
	c.deadlineAccess.Lock()
	select {
	case <-c.initDone:
		conn := c.conn
		c.deadlineAccess.Unlock()
		if conn != nil {
			return conn.SetDeadline(deadline)
		}
		return nil
	default:
	}
	c.readDeadline = deadline
	c.writeDeadline = deadline
	c.readTimer.Set(deadline)
	c.writeTimer.Set(deadline)
	initializing := c.initializing
	c.deadlineAccess.Unlock()
	if initializing != nil {
		return initializing.SetWriteDeadline(deadline)
	}
	return nil
}

func (c *v5LazyPacketConn) SetReadDeadline(deadline time.Time) error {
	c.deadlineAccess.Lock()
	select {
	case <-c.initDone:
		conn := c.conn
		c.deadlineAccess.Unlock()
		if conn != nil {
			return conn.SetReadDeadline(deadline)
		}
		return nil
	default:
	}
	c.readDeadline = deadline
	c.readTimer.Set(deadline)
	c.deadlineAccess.Unlock()
	return nil
}

func (c *v5LazyPacketConn) SetWriteDeadline(deadline time.Time) error {
	c.deadlineAccess.Lock()
	select {
	case <-c.initDone:
		conn := c.conn
		c.deadlineAccess.Unlock()
		if conn != nil {
			return conn.SetWriteDeadline(deadline)
		}
		return nil
	default:
	}
	c.writeDeadline = deadline
	c.writeTimer.Set(deadline)
	initializing := c.initializing
	c.deadlineAccess.Unlock()
	if initializing != nil {
		return initializing.SetWriteDeadline(deadline)
	}
	return nil
}

type packetConnWrapper struct {
	net.PacketConn
	destination M.Socksaddr
}

func (c *packetConnWrapper) Read(p []byte) (int, error) {
	n, _, err := c.ReadFrom(p)
	return n, err
}

func (c *packetConnWrapper) Write(p []byte) (int, error) {
	return c.WriteTo(p, c.destination)
}

func (c *packetConnWrapper) RemoteAddr() net.Addr { return c.destination }
