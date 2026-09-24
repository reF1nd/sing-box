package local

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/tls"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	dnsTransport "github.com/sagernet/sing-box/dns/transport"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/resolved"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	"github.com/godbus/dbus/v5"
	mDNS "github.com/miekg/dns"
)

func isSystemdResolvedManaged() bool {
	resolvContent, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return false
	}
	defer resolvContent.Close()
	scanner := bufio.NewScanner(resolvContent)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] != '#' {
			return false
		}
		if strings.Contains(line, "systemd-resolved") {
			return true
		}
	}
	return false
}

type DBusResolvedResolver struct {
	ctx               context.Context
	logger            logger.ContextLogger
	interfaceMonitor  tun.DefaultInterfaceMonitor
	interfaceCallback *list.Element[tun.DefaultInterfaceUpdateCallback]
	systemBus         *dbus.Conn
	savedServerSet    atomic.Pointer[resolvedServerSet]
	updateAccess      sync.Mutex
	updateCancel      context.CancelFunc
	updateRunAccess   sync.Mutex
	closed            bool
	closeOnce         sync.Once
	signalChan        chan *dbus.Signal
}

type resolvedServerSet struct {
	servers         []resolvedServer
	serverAddresses []netip.Addr
	signature       []string
	fallbackErr     error
}

type resolvedServer struct {
	primaryTransport  adapter.DNSTransport
	fallbackTransport adapter.DNSTransport
}

type resolvedServerSpecification struct {
	address    netip.Addr
	port       uint16
	serverName string
}

func NewResolvedResolver(ctx context.Context, logger logger.ContextLogger) (ResolvedResolver, error) {
	interfaceMonitor := service.FromContext[adapter.NetworkManager](ctx).InterfaceMonitor()
	if interfaceMonitor == nil {
		return nil, os.ErrInvalid
	}
	systemBus, err := dbus.ConnectSystemBus()
	if err != nil {
		return nil, err
	}
	return &DBusResolvedResolver{
		ctx:              ctx,
		logger:           logger,
		interfaceMonitor: interfaceMonitor,
		systemBus:        systemBus,
	}, nil
}

func (t *DBusResolvedResolver) Start() error {
	t.interfaceCallback = t.interfaceMonitor.RegisterCallback(t.updateDefaultInterface)
	err := t.systemBus.BusObject().AddMatchSignal(
		"org.freedesktop.DBus",
		"NameOwnerChanged",
		dbus.WithMatchSender("org.freedesktop.DBus"),
		dbus.WithMatchArg(0, "org.freedesktop.resolve1"),
	).Err
	if err != nil {
		t.Close()
		return E.Cause(err, "configure resolved restart listener")
	}
	err = t.systemBus.BusObject().AddMatchSignal(
		"org.freedesktop.DBus.Properties",
		"PropertiesChanged",
		dbus.WithMatchSender("org.freedesktop.resolve1"),
		dbus.WithMatchArg(0, "org.freedesktop.resolve1.Manager"),
	).Err
	if err != nil {
		t.Close()
		return E.Cause(err, "configure resolved properties listener")
	}
	t.signalChan = make(chan *dbus.Signal, 16)
	t.systemBus.Signal(t.signalChan)
	t.updateStatus(t.ctx)
	go t.loopUpdateStatus()
	return nil
}

func (t *DBusResolvedResolver) Close() error {
	var closeErr error
	t.closeOnce.Do(func() {
		t.updateAccess.Lock()
		updateCancel := t.updateCancel
		t.updateCancel = nil
		t.updateAccess.Unlock()
		if updateCancel != nil {
			updateCancel()
		}
		t.updateRunAccess.Lock()
		t.closed = true
		serverSet := t.savedServerSet.Swap(nil)
		t.updateRunAccess.Unlock()
		if serverSet != nil {
			closeErr = serverSet.Close()
		}
		if t.interfaceCallback != nil {
			t.interfaceMonitor.UnregisterCallback(t.interfaceCallback)
		}
		if t.systemBus != nil {
			_ = t.systemBus.Close()
		}
	})
	return closeErr
}

func (t *DBusResolvedResolver) Reset() {
	serverSet := t.savedServerSet.Load()
	if serverSet == nil {
		return
	}
	for _, server := range serverSet.servers {
		server.primaryTransport.Reset()
		if server.fallbackTransport != nil {
			server.fallbackTransport.Reset()
		}
	}
}

func (t *DBusResolvedResolver) Environment() []string {
	serverSet := t.savedServerSet.Load()
	if serverSet == nil {
		return nil
	}
	return serverSet.signature
}

func (t *DBusResolvedResolver) ServerAddresses() []netip.Addr {
	serverSet := t.savedServerSet.Load()
	if serverSet == nil {
		return nil
	}
	return serverSet.serverAddresses
}

func (t *DBusResolvedResolver) Fallback() bool {
	serverSet := t.savedServerSet.Load()
	return serverSet != nil && serverSet.fallbackErr != nil
}

func (t *DBusResolvedResolver) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	serverSet := t.savedServerSet.Load()
	if serverSet == nil {
		if err := t.updateStatus(ctx); err != nil {
			return nil, err
		}
		serverSet = t.savedServerSet.Load()
	}
	response, err := t.exchangeServerSet(ctx, message, serverSet)
	if err == nil || errors.Is(err, errResolvedUnavailable) || ctx.Err() != nil {
		return response, err
	}
	t.updateStatus(ctx)
	refreshedServerSet := t.savedServerSet.Load()
	if refreshedServerSet == nil || refreshedServerSet == serverSet || refreshedServerSet.fallbackErr != nil {
		return nil, err
	}
	return t.exchangeServerSet(ctx, message, refreshedServerSet)
}

func (t *DBusResolvedResolver) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(response *mDNS.Msg, err error)) {
	if err := ctx.Err(); err != nil {
		callback(nil, err)
		return
	}
	serverSet := t.savedServerSet.Load()
	if serverSet == nil {
		go func() {
			callback(t.Exchange(ctx, message))
		}()
		return
	}
	t.exchangeServerSetAsync(ctx, message, serverSet, func(response *mDNS.Msg, err error) {
		if err == nil || errors.Is(err, errResolvedUnavailable) || ctx.Err() != nil {
			callback(response, err)
			return
		}
		go func() {
			t.updateStatus(ctx)
			refreshedServerSet := t.savedServerSet.Load()
			if refreshedServerSet == nil || refreshedServerSet == serverSet || refreshedServerSet.fallbackErr != nil {
				callback(nil, err)
				return
			}
			t.exchangeServerSetAsync(ctx, message, refreshedServerSet, callback)
		}()
	})
}

func (t *DBusResolvedResolver) exchangeServerSetAsync(ctx context.Context, message *mDNS.Msg, serverSet *resolvedServerSet, callback func(response *mDNS.Msg, err error)) {
	if serverSet.fallbackErr != nil {
		callback(nil, serverSet.fallbackErr)
		return
	}
	if len(serverSet.servers) == 0 {
		callback(nil, E.New("link has no DNS servers configured"))
		return
	}
	serverExchangers := make([]dnsTransport.AsyncExchanger, 0, len(serverSet.servers))
	for _, server := range serverSet.servers {
		serverExchangers = append(serverExchangers, func(exchangeCtx context.Context, exchangeCallback func(response *mDNS.Msg, err error)) {
			server.primaryTransport.ExchangeAsync(exchangeCtx, message, func(response *mDNS.Msg, exchangeErr error) {
				if exchangeErr != nil && server.fallbackTransport != nil {
					server.fallbackTransport.ExchangeAsync(exchangeCtx, message, exchangeCallback)
					return
				}
				exchangeCallback(response, exchangeErr)
			})
		})
	}
	dnsTransport.ExchangeSequential(ctx, serverExchangers, nil, callback)
}

func (t *DBusResolvedResolver) loopUpdateStatus() {
	for signal := range t.signalChan {
		switch signal.Name {
		case "org.freedesktop.DBus.NameOwnerChanged":
			if len(signal.Body) != 3 {
				continue
			}
			_, loaded := signal.Body[2].(string)
			if !loaded {
				continue
			}
			t.postUpdateStatus()
		case "org.freedesktop.DBus.Properties.PropertiesChanged":
			if !shouldUpdateResolvedServerSet(signal) {
				continue
			}
			t.postUpdateStatus()
		}
	}
}

func (t *DBusResolvedResolver) postUpdateStatus() {
	updateContext, updateCancel := context.WithCancel(t.ctx)
	t.updateAccess.Lock()
	previousCancel := t.updateCancel
	t.updateCancel = updateCancel
	t.updateAccess.Unlock()
	if previousCancel != nil {
		previousCancel()
	}
	go func() {
		defer updateCancel()
		t.updateStatus(updateContext)
	}()
}

func (t *DBusResolvedResolver) updateStatus(ctx context.Context) error {
	t.updateRunAccess.Lock()
	defer t.updateRunAccess.Unlock()
	if t.closed {
		return os.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	serverSet, err := t.checkResolved(ctx)
	if ctx.Err() != nil {
		if serverSet != nil {
			_ = serverSet.Close()
		}
		return ctx.Err()
	}
	if isResolvedUnavailableError(err) {
		serverSet = &resolvedServerSet{fallbackErr: fmt.Errorf("%w: %w", errResolvedUnavailable, err)}
		err = nil
	}
	oldServerSet := t.savedServerSet.Swap(serverSet)
	if oldServerSet != nil {
		_ = oldServerSet.Close()
	}
	if serverSet != nil && serverSet.fallbackErr != nil {
		if oldServerSet == nil || oldServerSet.fallbackErr == nil || oldServerSet.fallbackErr.Error() != serverSet.fallbackErr.Error() {
			t.logger.Debug("using resolv.conf: ", serverSet.fallbackErr)
		}
		return nil
	}
	if err != nil {
		t.logger.Debug(E.Cause(err, "systemd-resolved service unavailable"))
		return err
	}
	if oldServerSet == nil || oldServerSet.fallbackErr != nil {
		t.logger.Debug("using systemd-resolved service as resolver")
	}
	return nil
}

// Only failures discovering the optional D-Bus interface permit resolv.conf fallback.
// DNS query failures, authorization failures and missing link DNS are not included.
func isResolvedUnavailableError(err error) bool {
	var value dbus.Error
	var pointer *dbus.Error
	var name string
	if errors.As(err, &value) {
		name = value.Name
	} else if errors.As(err, &pointer) {
		name = pointer.Name
	}
	switch name {
	case "org.freedesktop.DBus.Error.UnknownMethod", "org.freedesktop.DBus.Error.UnknownInterface",
		"org.freedesktop.DBus.Error.ServiceUnknown", "org.freedesktop.DBus.Error.NameHasNoOwner",
		"org.freedesktop.DBus.Error.Spawn.ServiceNotFound":
		return true
	default:
		return false
	}
}

func checkResolvedFallback(ctx context.Context, servers []M.Socksaddr) error {
	manager := service.FromContext[adapter.ServiceManager](ctx)
	if manager == nil {
		return nil
	}
	for _, current := range manager.Services() {
		resolver, ok := current.(*resolved.Service)
		if !ok {
			continue
		}
		for _, server := range servers {
			if resolver.IsDNSListener(server) {
				return E.New("local DNS fallback would loop into resolved service ", resolver.Tag(), " at ", server)
			}
		}
	}
	return nil
}

func (t *DBusResolvedResolver) exchangeServerSet(ctx context.Context, message *mDNS.Msg, serverSet *resolvedServerSet) (*mDNS.Msg, error) {
	if serverSet != nil && serverSet.fallbackErr != nil {
		return nil, serverSet.fallbackErr
	}
	if serverSet == nil || len(serverSet.servers) == 0 {
		return nil, E.New("link has no DNS servers configured")
	}
	var lastError error
	for _, server := range serverSet.servers {
		response, err := server.primaryTransport.Exchange(ctx, message)
		if err != nil && server.fallbackTransport != nil {
			response, err = server.fallbackTransport.Exchange(ctx, message)
		}
		if err != nil {
			lastError = err
			continue
		}
		return response, nil
	}
	return nil, lastError
}

func (t *DBusResolvedResolver) checkResolved(ctx context.Context) (*resolvedServerSet, error) {
	dbusObject := t.systemBus.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")
	err := dbusObject.(*dbus.Object).CallWithContext(ctx, "org.freedesktop.DBus.Peer.Ping", 0).Err
	if err != nil {
		return nil, err
	}
	defaultInterface := t.interfaceMonitor.DefaultInterface()
	if defaultInterface == nil {
		return nil, E.New("missing default interface")
	}
	call := dbusObject.(*dbus.Object).CallWithContext(
		ctx,
		"org.freedesktop.resolve1.Manager.GetLink",
		0,
		int32(defaultInterface.Index),
	)
	if call.Err != nil {
		return nil, call.Err
	}
	var linkPath dbus.ObjectPath
	err = call.Store(&linkPath)
	if err != nil {
		return nil, err
	}
	linkObject := t.systemBus.Object("org.freedesktop.resolve1", linkPath)
	if linkObject == nil {
		return nil, E.New("missing link object for default interface")
	}
	dnsOverTLSMode, err := loadResolvedLinkDNSOverTLS(linkObject)
	if err != nil {
		return nil, err
	}
	err = ctx.Err()
	if err != nil {
		return nil, err
	}
	linkDNSEx, err := loadResolvedLinkDNSEx(linkObject)
	if err != nil {
		return nil, err
	}
	err = ctx.Err()
	if err != nil {
		return nil, err
	}
	linkDNS, err := loadResolvedLinkDNS(linkObject)
	if err != nil {
		return nil, err
	}
	if len(linkDNSEx) == 0 && len(linkDNS) == 0 {
		for _, inbound := range service.FromContext[adapter.InboundManager](t.ctx).Inbounds() {
			if inbound.Type() == C.TypeTun {
				return nil, E.New("No appropriate name servers or networks for name found")
			}
		}
		return nil, E.New("link has no DNS servers configured")
	}
	serverDialer, err := dialer.NewDefault(t.ctx, option.DialerOptions{
		AbstractDialerOptions: option.AbstractDialerOptions{
			BindInterface:      defaultInterface.Name,
			UDPFragmentDefault: true,
		},
	})
	if err != nil {
		return nil, err
	}
	var serverSpecifications []resolvedServerSpecification
	if len(linkDNSEx) > 0 {
		for _, entry := range linkDNSEx {
			serverSpecification, loaded := buildResolvedServerSpecification(defaultInterface.Name, entry.Address, entry.Port, entry.Name)
			if !loaded {
				continue
			}
			serverSpecifications = append(serverSpecifications, serverSpecification)
		}
	} else {
		for _, entry := range linkDNS {
			serverSpecification, loaded := buildResolvedServerSpecification(defaultInterface.Name, entry.Address, 0, "")
			if !loaded {
				continue
			}
			serverSpecifications = append(serverSpecifications, serverSpecification)
		}
	}
	if len(serverSpecifications) == 0 {
		return nil, E.New("no valid DNS servers on link")
	}
	serverSet := &resolvedServerSet{
		servers: make([]resolvedServer, 0, len(serverSpecifications)),
		serverAddresses: common.Map(serverSpecifications, func(it resolvedServerSpecification) netip.Addr {
			return it.address
		}),
		signature: common.Map(serverSpecifications, func(it resolvedServerSpecification) string {
			return M.SocksaddrFrom(it.address, it.port).String()
		}),
	}
	for _, serverSpecification := range serverSpecifications {
		server, createErr := t.createResolvedServer(serverDialer, dnsOverTLSMode, serverSpecification)
		if createErr != nil {
			_ = serverSet.Close()
			return nil, createErr
		}
		serverSet.servers = append(serverSet.servers, server)
	}
	return serverSet, nil
}

func (t *DBusResolvedResolver) createResolvedServer(serverDialer N.Dialer, dnsOverTLSMode string, serverSpecification resolvedServerSpecification) (resolvedServer, error) {
	if dnsOverTLSMode == "yes" {
		primaryTransport, err := t.createResolvedTransport(serverDialer, serverSpecification, true)
		if err != nil {
			return resolvedServer{}, err
		}
		return resolvedServer{
			primaryTransport: primaryTransport,
		}, nil
	}
	if dnsOverTLSMode == "opportunistic" {
		primaryTransport, err := t.createResolvedTransport(serverDialer, serverSpecification, true)
		if err != nil {
			return resolvedServer{}, err
		}
		fallbackTransport, err := t.createResolvedTransport(serverDialer, serverSpecification, false)
		if err != nil {
			_ = primaryTransport.Close()
			return resolvedServer{}, err
		}
		return resolvedServer{
			primaryTransport:  primaryTransport,
			fallbackTransport: fallbackTransport,
		}, nil
	}
	primaryTransport, err := t.createResolvedTransport(serverDialer, serverSpecification, false)
	if err != nil {
		return resolvedServer{}, err
	}
	return resolvedServer{
		primaryTransport: primaryTransport,
	}, nil
}

func (t *DBusResolvedResolver) createResolvedTransport(serverDialer N.Dialer, serverSpecification resolvedServerSpecification, useTLS bool) (adapter.DNSTransport, error) {
	serverAddress := M.SocksaddrFrom(serverSpecification.address, resolvedServerPort(serverSpecification.port, useTLS))
	if useTLS {
		tlsAddress := serverSpecification.address
		if tlsAddress.Zone() != "" {
			tlsAddress = tlsAddress.WithZone("")
		}
		serverName := serverSpecification.serverName
		if serverName == "" {
			serverName = tlsAddress.String()
		}
		tlsConfig, err := tls.NewClient(t.ctx, t.logger, tlsAddress.String(), option.OutboundTLSOptions{
			Enabled:    true,
			ServerName: serverName,
		})
		if err != nil {
			return nil, err
		}
		serverTransport := dnsTransport.NewTLSRaw(t.logger, dns.NewTransportAdapter(C.DNSTypeTLS, "", nil), serverDialer, serverAddress, tlsConfig)
		err = serverTransport.Start(adapter.StartStateStart)
		if err != nil {
			_ = serverTransport.Close()
			return nil, err
		}
		return serverTransport, nil
	}
	serverTransport := dnsTransport.NewUDPRaw(t.logger, dns.NewTransportAdapter(C.DNSTypeUDP, "", nil), serverDialer, serverAddress)
	err := serverTransport.Start(adapter.StartStateStart)
	if err != nil {
		_ = serverTransport.Close()
		return nil, err
	}
	return serverTransport, nil
}

func (s *resolvedServerSet) Close() error {
	var errors []error
	for _, server := range s.servers {
		errors = append(errors, server.primaryTransport.Close())
		if server.fallbackTransport != nil {
			errors = append(errors, server.fallbackTransport.Close())
		}
	}
	return E.Errors(errors...)
}

func buildResolvedServerSpecification(interfaceName string, rawAddress []byte, port uint16, serverName string) (resolvedServerSpecification, bool) {
	address, loaded := netip.AddrFromSlice(rawAddress)
	if !loaded {
		return resolvedServerSpecification{}, false
	}
	if address.Is6() && address.IsLinkLocalUnicast() && address.Zone() == "" {
		address = address.WithZone(interfaceName)
	}
	return resolvedServerSpecification{
		address:    address,
		port:       port,
		serverName: serverName,
	}, true
}

func resolvedServerPort(port uint16, useTLS bool) uint16 {
	if port > 0 {
		return port
	}
	if useTLS {
		return 853
	}
	return 53
}

func loadResolvedLinkDNS(linkObject dbus.BusObject) ([]resolved.LinkDNS, error) {
	dnsProperty, err := linkObject.GetProperty("org.freedesktop.resolve1.Link.DNS")
	if err != nil {
		if isResolvedUnknownPropertyError(err) {
			return nil, nil
		}
		return nil, err
	}
	var linkDNS []resolved.LinkDNS
	err = dnsProperty.Store(&linkDNS)
	if err != nil {
		return nil, err
	}
	return linkDNS, nil
}

func loadResolvedLinkDNSEx(linkObject dbus.BusObject) ([]resolved.LinkDNSEx, error) {
	dnsProperty, err := linkObject.GetProperty("org.freedesktop.resolve1.Link.DNSEx")
	if err != nil {
		if isResolvedUnknownPropertyError(err) {
			return nil, nil
		}
		return nil, err
	}
	var linkDNSEx []resolved.LinkDNSEx
	err = dnsProperty.Store(&linkDNSEx)
	if err != nil {
		return nil, err
	}
	return linkDNSEx, nil
}

func loadResolvedLinkDNSOverTLS(linkObject dbus.BusObject) (string, error) {
	dnsOverTLSProperty, err := linkObject.GetProperty("org.freedesktop.resolve1.Link.DNSOverTLS")
	if err != nil {
		if isResolvedUnknownPropertyError(err) {
			return "", nil
		}
		return "", err
	}
	var dnsOverTLSMode string
	err = dnsOverTLSProperty.Store(&dnsOverTLSMode)
	if err != nil {
		return "", err
	}
	return dnsOverTLSMode, nil
}

func isResolvedUnknownPropertyError(err error) bool {
	var dbusError dbus.Error
	return errors.As(err, &dbusError) && dbusError.Name == "org.freedesktop.DBus.Error.UnknownProperty"
}

func shouldUpdateResolvedServerSet(signal *dbus.Signal) bool {
	if len(signal.Body) != 3 {
		return true
	}
	changedProperties, loaded := signal.Body[1].(map[string]dbus.Variant)
	if !loaded {
		return true
	}
	for propertyName := range changedProperties {
		switch propertyName {
		case "DNS", "DNSEx", "DNSOverTLS":
			return true
		}
	}
	invalidatedProperties, loaded := signal.Body[2].([]string)
	if !loaded {
		return true
	}
	for _, propertyName := range invalidatedProperties {
		switch propertyName {
		case "DNS", "DNSEx", "DNSOverTLS":
			return true
		}
	}
	return false
}

func (t *DBusResolvedResolver) updateDefaultInterface(defaultInterface *control.Interface, flags int) {
	t.postUpdateStatus()
}
