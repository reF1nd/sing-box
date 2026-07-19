package wireguard

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/service/powerreport"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/pause"
	"github.com/sagernet/wireguard-go/conn"
	"github.com/sagernet/wireguard-go/device"

	"go4.org/netipx"
)

const networkPauseGracePeriod = time.Second

var errNetworkPaused = E.New("network is paused")

type Endpoint struct {
	options        EndpointOptions
	peers          []peerConfig
	ipcConf        string
	allowedAddress []netip.Prefix
	tunDevice      Device
	returnDevice   *returnDeviceWrapper
	device         atomic.Pointer[device.Device]
	allowedIPs     *device.AllowedIPs
	egressPool     *tun.UDPEgressPool
	pause          pause.Manager
	pauseCallback  *list.Element[pause.Callback]
	stateAccess    sync.Mutex
	suspended      atomic.Bool
	networkPaused  bool
	pauseAccess    sync.Mutex
	pauseUpdated   chan struct{}
	done           chan struct{}
	closeOnce      sync.Once
	closeErr       error
}

func NewEndpoint(options EndpointOptions) (*Endpoint, error) {
	if options.PrivateKey == "" {
		return nil, E.New("missing private key")
	}
	privateKeyBytes, err := base64.StdEncoding.DecodeString(options.PrivateKey)
	if err != nil {
		return nil, E.Cause(err, "decode private key")
	}
	privateKey := hex.EncodeToString(privateKeyBytes)
	ipcConf := "private_key=" + privateKey
	if options.ListenPort != 0 {
		ipcConf += "\nlisten_port=" + F.ToString(options.ListenPort)
	}
	var peers []peerConfig
	for peerIndex, rawPeer := range options.Peers {
		peer := peerConfig{
			allowedIPs: rawPeer.AllowedIPs,
			keepalive:  rawPeer.PersistentKeepaliveInterval,
		}
		if rawPeer.Endpoint.Addr.IsValid() {
			peer.endpoint = rawPeer.Endpoint.AddrPort()
		} else if rawPeer.Endpoint.IsDomain() {
			peer.destination = rawPeer.Endpoint
		}
		publicKeyBytes, err := base64.StdEncoding.DecodeString(rawPeer.PublicKey)
		if err != nil {
			return nil, E.Cause(err, "decode public key for peer ", peerIndex)
		}
		peer.publicKeyHex = hex.EncodeToString(publicKeyBytes)
		if rawPeer.PreSharedKey != "" {
			preSharedKeyBytes, err := base64.StdEncoding.DecodeString(rawPeer.PreSharedKey)
			if err != nil {
				return nil, E.Cause(err, "decode pre shared key for peer ", peerIndex)
			}
			peer.preSharedKeyHex = hex.EncodeToString(preSharedKeyBytes)
		}
		if len(rawPeer.AllowedIPs) == 0 {
			return nil, E.New("missing allowed ips for peer ", peerIndex)
		}
		if len(rawPeer.Reserved) > 0 {
			if len(rawPeer.Reserved) != 3 {
				return nil, E.New("invalid reserved value for peer ", peerIndex, ", required 3 bytes, got ", len(peer.reserved))
			}
			copy(peer.reserved[:], rawPeer.Reserved[:])
		}
		peers = append(peers, peer)
	}
	var allowedPrefixBuilder netipx.IPSetBuilder
	for _, peer := range options.Peers {
		for _, prefix := range peer.AllowedIPs {
			allowedPrefixBuilder.AddPrefix(prefix)
		}
	}
	allowedIPSet, err := allowedPrefixBuilder.IPSet()
	if err != nil {
		return nil, err
	}
	allowedAddresses := allowedIPSet.Prefixes()
	if options.MTU == 0 {
		options.MTU = 1408
	}
	deviceOptions := DeviceOptions{
		Context:         options.Context,
		Logger:          options.Logger,
		System:          options.System,
		GSO:             options.GSO,
		Handler:         options.Handler,
		UDPTimeout:      options.UDPTimeout,
		ICMPTimeout:     options.ICMPTimeout,
		UDPMapping:      options.UDPMapping,
		UDPFiltering:    options.UDPFiltering,
		UDPNATMax:       options.UDPNATMax,
		InterfaceFinder: options.InterfaceFinder,
		CreateDialer:    options.CreateDialer,
		Name:            options.Name,
		MTU:             options.MTU,
		Address:         options.Address,
		AllowedAddress:  allowedAddresses,
	}
	tunDevice, err := NewDevice(deviceOptions)
	if err != nil {
		return nil, E.Cause(err, "create WireGuard device")
	}
	return &Endpoint{
		options:        options,
		peers:          peers,
		ipcConf:        ipcConf,
		allowedAddress: allowedAddresses,
		tunDevice:      tunDevice,
		returnDevice:   &returnDeviceWrapper{Device: tunDevice},
		pauseUpdated:   make(chan struct{}),
		done:           make(chan struct{}),
	}, nil
}

func (e *Endpoint) Start(postStart bool) error {
	hasDomainPeer := common.Any(e.peers, func(peer peerConfig) bool {
		return peer.destination.IsDomain()
	})
	if postStart != hasDomainPeer {
		return nil
	}
	var bind conn.Bind
	udpListener, isUDPListener := common.Cast[dialer.UDPListener](e.options.Dialer)
	if isUDPListener {
		listenerControl, egressEnabled := udpListener.UDPListenerControl()
		standardBind := conn.NewStdNetBind(listenerControl).(*conn.StdNetBind)
		if e.options.ListenPort == 0 && len(e.peers) == 1 && e.peers[0].endpoint.IsValid() {
			standardBind.SetSinglePeerMode()
		}
		if egressEnabled {
			egressPoolOptions := e.options.EgressPoolOptions
			egressPoolOptions.Control = listenerControl
			e.egressPool = tun.NewUDPEgressPool(egressPoolOptions)
			standardBind.SetEgressProvider(e.egressPool)
		}
		powerManager := service.FromContext[*powerreport.Manager](e.options.Context)
		if powerManager != nil {
			recorder := powerManager.Recorder()
			if recorder != nil {
				attribution := &powerreport.Attribution{Endpoint: e.options.Tag}
				counter := recorder.TrafficCounter(powerreport.TrafficEndpoint, e.options.Tag)
				standardBind.SetIOActivityFuncs(func(size int) {
					counter.CountIn(int64(size))
					recorder.Touch(powerreport.DirectionInbound, size, attribution)
				}, func(size int) {
					counter.CountOut(int64(size))
					recorder.Touch(powerreport.DirectionOutbound, size, attribution)
				})
			}
		}
		bind = standardBind
	} else {
		var (
			isConnect   bool
			connectAddr netip.AddrPort
			reserved    [3]uint8
		)
		if len(e.peers) == 1 {
			reserved = e.peers[0].reserved
			if e.peers[0].endpoint.IsValid() {
				isConnect = true
				connectAddr = e.peers[0].endpoint
			}
		}
		bind = NewClientBind(e.options.Context, e.options.Logger, e.options.Dialer, isConnect, connectAddr, reserved)
	}
	if isUDPListener || len(e.peers) > 1 {
		for _, peer := range e.peers {
			if peer.endpoint.IsValid() && peer.reserved != [3]uint8{} {
				bind.SetReservedForEndpoint(peer.endpoint, peer.reserved)
			}
		}
	}
	err := e.tunDevice.Start()
	if err != nil {
		return err
	}
	logger := &device.Logger{
		Verbosef: func(format string, args ...any) {
			e.options.Logger.Debug(fmt.Sprintf(strings.ToLower(format), args...))
		},
		Errorf: func(format string, args ...any) {
			e.options.Logger.Error(fmt.Sprintf(strings.ToLower(format), args...))
		},
	}
	wgDevice := device.NewDevice(e.options.Context, e.returnDevice, bind, logger, e.options.Workers)
	e.tunDevice.SetDevice(wgDevice)
	var ipcConf strings.Builder
	ipcConf.WriteString(e.ipcConf)
	for _, peer := range e.peers {
		ipcConf.WriteString(peer.GenerateIpcLines())
	}
	err = wgDevice.IpcSet(ipcConf.String())
	if err != nil {
		wgDevice.Close()
		return E.Cause(err, "setup wireguard: \n", ipcConf.String())
	}
	for _, peer := range e.peers {
		if !peer.destination.IsDomain() {
			continue
		}
		var publicKey device.NoisePublicKey
		common.Must(publicKey.FromHex(peer.publicKeyHex))
		wgPeer, found := wgDevice.LookupActivePeer(publicKey)
		if !found {
			wgDevice.Close()
			return E.New("missing configured peer: ", peer.destination)
		}
		wgPeer.SetEndpointResolver(func() ([]conn.Endpoint, error) {
			addresses, lookupErr := e.options.ResolvePeer(peer.destination.Fqdn)
			if lookupErr != nil {
				return nil, lookupErr
			}
			endpoints := make([]conn.Endpoint, 0, len(addresses))
			for _, address := range addresses {
				destination := netip.AddrPortFrom(address, peer.destination.Port)
				if peer.reserved != ([3]uint8{}) {
					bind.SetReservedForEndpoint(destination, peer.reserved)
				}
				endpoint, parseErr := bind.ParseEndpoint(destination.String())
				if parseErr != nil {
					return nil, parseErr
				}
				endpoints = append(endpoints, endpoint)
			}
			return endpoints, nil
		})
	}
	e.device.Store(wgDevice)
	e.pause = service.FromContext[pause.Manager](e.options.Context)
	if e.pause != nil {
		e.pauseCallback = e.pause.RegisterCallback(e.onPauseUpdated)
	}
	e.allowedIPs = wgDevice.AllowedIPs()
	return nil
}

func (e *Endpoint) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	if err := e.ensureDeviceStarted(ctx); err != nil {
		return nil, err
	}
	return e.tunDevice.DialContext(ctx, network, destination)
}

func (e *Endpoint) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if !destination.Addr.IsValid() {
		return nil, E.Cause(os.ErrInvalid, "invalid non-IP destination")
	}
	if err := e.ensureDeviceStarted(ctx); err != nil {
		return nil, err
	}
	return e.tunDevice.ListenPacket(ctx, destination)
}

func (e *Endpoint) SetIdle(idle bool) {
	e.stateAccess.Lock()
	defer e.stateAccess.Unlock()
	wgDevice := e.device.Load()
	if wgDevice == nil {
		return
	}
	if idle {
		if e.suspended.Load() {
			return
		}
		e.suspended.Store(true)
		wgDevice.Down()
	} else if e.options.System {
		e.resumeLocked(wgDevice)
	}
}

func (e *Endpoint) resumeLocked(wgDevice *device.Device) {
	if !e.suspended.Load() {
		return
	}
	e.suspended.Store(false)
	if !e.networkPaused {
		wgDevice.Up()
	}
}

func (e *Endpoint) ensureDeviceStarted(ctx context.Context) error {
	if err := e.waitNetworkActive(ctx); err != nil {
		return err
	}
	e.stateAccess.Lock()
	defer e.stateAccess.Unlock()
	select {
	case <-e.done:
		return net.ErrClosed
	default:
	}
	wgDevice := e.device.Load()
	if wgDevice == nil {
		return net.ErrClosed
	}
	if e.pause != nil && e.pause.IsPaused() {
		return errNetworkPaused
	}
	e.suspended.Store(false)
	return wgDevice.Up()
}

func (e *Endpoint) waitNetworkActive(ctx context.Context) error {
	pauseManager := e.pause
	if pauseManager == nil || !pauseManager.IsPaused() {
		return nil
	}
	timer := time.NewTimer(networkPauseGracePeriod)
	defer timer.Stop()
	for pauseManager.IsPaused() {
		e.pauseAccess.Lock()
		updated := e.pauseUpdated
		e.pauseAccess.Unlock()
		if !pauseManager.IsPaused() {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-e.options.Context.Done():
			return net.ErrClosed
		case <-e.done:
			return net.ErrClosed
		case <-updated:
		case <-timer.C:
			if pauseManager.IsPaused() {
				return errNetworkPaused
			}
		}
	}
	return nil
}

func (e *Endpoint) notifyPauseUpdated() {
	e.pauseAccess.Lock()
	close(e.pauseUpdated)
	e.pauseUpdated = make(chan struct{})
	e.pauseAccess.Unlock()
}

func (e *Endpoint) Close() error {
	e.closeOnce.Do(func() {
		close(e.done)
		if e.pauseCallback != nil {
			e.pause.UnregisterCallback(e.pauseCallback)
			e.pauseCallback = nil
		}
		if e.egressPool != nil {
			e.egressPool.Close()
			e.egressPool = nil
		}
		e.stateAccess.Lock()
		defer e.stateAccess.Unlock()
		wgDevice := e.device.Swap(nil)
		if wgDevice != nil {
			wgDevice.Down()
			wgDevice.Close()
		} else if e.tunDevice != nil {
			e.closeErr = e.tunDevice.Close()
		}
	})
	return e.closeErr
}

func (e *Endpoint) Lookup(address netip.Addr) *device.Peer {
	if e.allowedIPs == nil {
		return nil
	}
	return e.allowedIPs.LookupFromPacket(netip.Addr{}, address, nil)
}

func (e *Endpoint) BindUpdate() error {
	if e.pause != nil && e.pause.IsPaused() {
		return nil
	}
	e.stateAccess.Lock()
	defer e.stateAccess.Unlock()
	if e.pause != nil && e.pause.IsPaused() {
		return nil
	}
	wgDevice := e.device.Load()
	if wgDevice == nil {
		return nil
	}
	return wgDevice.BindUpdate()
}

func (e *Endpoint) onPauseUpdated(event int) {
	defer e.notifyPauseUpdated()
	e.stateAccess.Lock()
	defer e.stateAccess.Unlock()
	wgDevice := e.device.Load()
	if wgDevice == nil {
		return
	}
	var err error
	switch event {
	case pause.EventNetworkPause:
		e.networkPaused = true
		err = wgDevice.Down()
	case pause.EventNetworkWake:
		e.networkPaused = false
		if e.pause.IsPaused() || e.suspended.Load() {
			return
		}
		err = wgDevice.Up()
	}
	if err != nil {
		e.options.Logger.Warn(E.Cause(err, "update WireGuard device state"))
	}
}

type peerConfig struct {
	destination     M.Socksaddr
	endpoint        netip.AddrPort
	publicKeyHex    string
	preSharedKeyHex string
	allowedIPs      []netip.Prefix
	keepalive       uint16
	reserved        [3]uint8
}

func (c peerConfig) GenerateIpcLines() string {
	var ipcLines strings.Builder
	ipcLines.WriteString("\npublic_key=" + c.publicKeyHex)
	if c.endpoint.IsValid() {
		ipcLines.WriteString("\nendpoint=" + c.endpoint.String())
	}
	if c.preSharedKeyHex != "" {
		ipcLines.WriteString("\npreshared_key=" + c.preSharedKeyHex)
	}
	for _, allowedIP := range c.allowedIPs {
		ipcLines.WriteString("\nallowed_ip=" + allowedIP.String())
	}
	if c.keepalive > 0 {
		ipcLines.WriteString("\npersistent_keepalive_interval=" + F.ToString(c.keepalive))
	}
	return ipcLines.String()
}
