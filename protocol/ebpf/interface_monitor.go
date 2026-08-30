//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"
)

type tcInterfaceMonitor struct {
	access                   sync.Mutex
	network                  tun.NetworkUpdateMonitor
	networkOwned             bool
	networkCallback          *list.Element[tun.NetworkUpdateCallback]
	defaultInterface         tun.DefaultInterfaceMonitor
	defaultInterfaceOwned    bool
	defaultInterfaceCallback *list.Element[tun.DefaultInterfaceUpdateCallback]
	defaultInterfaceName     string
	cancel                   context.CancelFunc
	updates                  chan struct{}
}

func (i *Inbound) InterfaceUpdated(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	i.setDefaultInterfaceName(i.currentDefaultInterfaceName())
}

func (i *Inbound) startTCInterfaceMonitor() error {
	networkMonitor := i.networkManager.NetworkMonitor()
	networkOwned := false
	if networkMonitor == nil {
		var err error
		networkMonitor, err = tun.NewNetworkUpdateMonitor(i.logger)
		if err != nil {
			return E.Cause(err, "create TC eBPF network monitor")
		}
		networkOwned = true
	}
	defaultInterfaceMonitor := i.networkManager.InterfaceMonitor()
	defaultInterfaceOwned := false
	if defaultInterfaceMonitor == nil {
		var err error
		defaultInterfaceMonitor, err = tun.NewDefaultInterfaceMonitor(networkMonitor, i.logger, tun.DefaultInterfaceMonitorOptions{
			InterfaceFinder: i.networkManager.InterfaceFinder(),
		})
		if err != nil {
			if networkOwned {
				_ = networkMonitor.Close()
			}
			return E.Cause(err, "create TC eBPF default interface monitor")
		}
		defaultInterfaceOwned = true
	}
	monitorContext, cancel := context.WithCancel(i.ctx)
	updates := make(chan struct{}, 1)
	state := &i.interfaceMonitor
	state.access.Lock()
	if state.network != nil {
		state.access.Unlock()
		cancel()
		if defaultInterfaceOwned {
			_ = defaultInterfaceMonitor.Close()
		}
		if networkOwned {
			_ = networkMonitor.Close()
		}
		return nil
	}
	state.network = networkMonitor
	state.networkOwned = networkOwned
	state.defaultInterface = defaultInterfaceMonitor
	state.defaultInterfaceOwned = defaultInterfaceOwned
	state.cancel = cancel
	state.updates = updates
	state.networkCallback = networkMonitor.RegisterCallback(i.notifyTCInterfaceUpdate)
	state.defaultInterfaceCallback = defaultInterfaceMonitor.RegisterCallback(i.defaultInterfaceUpdated)
	state.defaultInterfaceName = interfaceName(defaultInterfaceMonitor.DefaultInterface())
	state.access.Unlock()
	go i.runTCInterfaceUpdates(monitorContext, updates)
	if networkOwned {
		if err := networkMonitor.Start(); err != nil {
			return E.Errors(E.Cause(err, "start TC eBPF network monitor"), i.stopTCInterfaceMonitor())
		}
	}
	if defaultInterfaceOwned {
		if err := defaultInterfaceMonitor.Start(); err != nil {
			return E.Errors(E.Cause(err, "start TC eBPF default interface monitor"), i.stopTCInterfaceMonitor())
		}
	}
	i.notifyTCInterfaceUpdate()
	return nil
}

func (i *Inbound) stopTCInterfaceMonitor() error {
	state := &i.interfaceMonitor
	state.access.Lock()
	networkMonitor := state.network
	networkOwned := state.networkOwned
	networkCallback := state.networkCallback
	defaultInterfaceMonitor := state.defaultInterface
	defaultInterfaceOwned := state.defaultInterfaceOwned
	defaultInterfaceCallback := state.defaultInterfaceCallback
	cancel := state.cancel
	state.network = nil
	state.networkOwned = false
	state.networkCallback = nil
	state.defaultInterface = nil
	state.defaultInterfaceOwned = false
	state.defaultInterfaceCallback = nil
	state.defaultInterfaceName = ""
	state.cancel = nil
	state.updates = nil
	state.access.Unlock()
	if networkMonitor == nil {
		return nil
	}
	if networkCallback != nil {
		networkMonitor.UnregisterCallback(networkCallback)
	}
	if defaultInterfaceMonitor != nil && defaultInterfaceCallback != nil {
		defaultInterfaceMonitor.UnregisterCallback(defaultInterfaceCallback)
	}
	if cancel != nil {
		cancel()
	}
	var closeErr error
	if defaultInterfaceOwned {
		closeErr = defaultInterfaceMonitor.Close()
	}
	if networkOwned {
		closeErr = E.Errors(closeErr, networkMonitor.Close())
	}
	return closeErr
}

func (i *Inbound) defaultInterfaceUpdated(defaultInterface *control.Interface, _ int) {
	i.setDefaultInterfaceName(interfaceName(defaultInterface))
}

func interfaceName(networkInterface *control.Interface) string {
	if networkInterface == nil {
		return ""
	}
	return networkInterface.Name
}

func (i *Inbound) currentDefaultInterfaceName() string {
	defaultInterfaceMonitor := i.networkManager.InterfaceMonitor()
	if defaultInterfaceMonitor == nil {
		return ""
	}
	return interfaceName(defaultInterfaceMonitor.DefaultInterface())
}

func (i *Inbound) setDefaultInterfaceName(interfaceName string) {
	state := &i.interfaceMonitor
	state.access.Lock()
	state.defaultInterfaceName = interfaceName
	updates := state.updates
	active := state.network != nil && updates != nil
	state.access.Unlock()
	if active {
		notifyTCInterfaceUpdate(updates)
	}
}

func (i *Inbound) notifyTCInterfaceUpdate() {
	state := &i.interfaceMonitor
	state.access.Lock()
	updates := state.updates
	active := state.network != nil && updates != nil
	state.access.Unlock()
	if !active {
		return
	}
	notifyTCInterfaceUpdate(updates)
}

func notifyTCInterfaceUpdate(updates chan<- struct{}) {
	select {
	case updates <- struct{}{}:
	default:
	}
}

func (i *Inbound) runTCInterfaceUpdates(ctx context.Context, updates <-chan struct{}) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-updates:
			i.updateTCInterfaces(ctx)
		}
	}
}

func (i *Inbound) updateTCInterfaces(ctx context.Context) {
	if ctx.Err() != nil {
		return
	}
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	if ctx.Err() != nil {
		return
	}
	if err := i.networkManager.UpdateInterfaces(); err != nil {
		i.interfaceWarnings.inventory.warn(i.logger, "update interfaces for TC eBPF: ", err)
	}
	defaultInterface := i.monitoredDefaultInterfaceName()
	localInterface, err := availableLocalTCInterface(i.localEnabled, defaultInterface)
	if err != nil {
		i.interfaceWarnings.topology.warn(i.logger, "inspect TC eBPF local interface: ", err)
		return
	}
	if i.localEnabled && localInterface == "" {
		i.interfaceWarnings.defaultInterface.warn(i.logger, "default interface unavailable; retaining previous local TC attachment")
	}
	sharedInterfaces := activeSharedInterfaces(i.sharedOptions.Interface, defaultInterface)
	infrastructureChanged, err := i.repairTCInfrastructure()
	infrastructureHealthy := err == nil
	if err != nil {
		i.interfaceWarnings.infrastructure.warn(i.logger, "repair TC eBPF network state: ", err)
	}
	changed, err := i.tcAttachmentStateChanged(localInterface, sharedInterfaces)
	if err != nil {
		i.interfaceWarnings.topology.warn(i.logger, "inspect TC eBPF interfaces: ", err)
		return
	}
	hostAddresses := i.hostAddresses()
	if !changed {
		if err = i.updateTCHostAddresses(hostAddresses); err != nil {
			i.interfaceWarnings.hostPolicy.warn(i.logger, "refresh TC eBPF host addresses: ", err)
		}
		if infrastructureChanged && infrastructureHealthy {
			i.logger.Debug("eBPF TC network state restored")
		}
		return
	}
	previousAttachments := i.tcAttachmentDescriptions()
	i.udpNat.Purge()
	if err = i.udpReplySockets.reset(); err != nil {
		i.interfaceWarnings.reconcile.warn(i.logger, "reset TC eBPF UDP reply sockets: ", err)
	}
	if err = i.reconcileTCDataPlane(localInterface, sharedInterfaces, hostAddresses); err != nil {
		i.interfaceWarnings.reconcile.warn(i.logger, "refresh TC eBPF interfaces: ", err)
		return
	}
	attachments := i.tcAttachmentDescriptions()
	if !slices.Equal(previousAttachments, attachments) {
		i.logger.Debug(
			"eBPF TC attachments updated: attachments=[",
			strings.Join(attachments, ", "),
			"]",
		)
	}
}

func (i *Inbound) repairTCInfrastructure() (bool, error) {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return false, nil
	}
	return i.tcDataPlane.repairInfrastructure()
}

func (i *Inbound) monitoredDefaultInterfaceName() string {
	state := &i.interfaceMonitor
	state.access.Lock()
	defer state.access.Unlock()
	return state.defaultInterfaceName
}

func availableLocalTCInterface(enabled bool, interfaceName string) (string, error) {
	if !enabled || interfaceName == "" {
		return "", nil
	}
	_, err := netlink.LinkByName(interfaceName)
	if err != nil && tcLinkNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", E.Cause(err, "find local TC eBPF interface ", interfaceName)
	}
	return interfaceName, nil
}

func activeSharedInterfaces(configured []string, defaultInterface string) []string {
	return slices.DeleteFunc(slices.Clone(configured), func(interfaceName string) bool {
		return interfaceName == defaultInterface
	})
}

func (i *Inbound) tcAttachmentStateChanged(localInterface string, sharedInterfaces []string) (bool, error) {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return false, nil
	}
	return i.tcDataPlane.attachmentStateChanged(localInterface, sharedInterfaces)
}

func (i *Inbound) tcAttachmentDescriptions() []string {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.attachmentDescriptions()
}

func (i *Inbound) updateTCHostAddresses(hostAddresses []netip.Addr) error {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.updateHostAddresses(hostAddresses)
}

func (i *Inbound) hostAddresses() []netip.Addr {
	return collectHostAddresses(i.networkManager.InterfaceFinder().Interfaces())
}

func collectHostAddresses(interfaces []control.Interface) []netip.Addr {
	var addresses []netip.Addr
	for _, networkInterface := range interfaces {
		for _, prefix := range networkInterface.Addresses {
			if !prefix.IsValid() {
				continue
			}
			address := prefix.Addr().Unmap()
			if address.IsUnspecified() || address.IsLoopback() {
				continue
			}
			addresses = append(addresses, address)
		}
	}
	slices.SortFunc(addresses, func(left, right netip.Addr) int {
		return left.Compare(right)
	})
	addresses = slices.Compact(addresses)
	return addresses
}

func (d *tcDataPlane) attachmentStateChanged(localInterface string, sharedInterfaces []string) (bool, error) {
	d.access.Lock()
	defer d.access.Unlock()
	desired, err := d.desiredAttachmentState(localInterface, sharedInterfaces)
	if err != nil {
		return false, err
	}
	if tcAttachmentTopologyChanged(d.attachments, desired) {
		return true, nil
	}
	for _, attachment := range d.attachments {
		if localInterface == "" && attachment.role.local {
			if _, err = netlink.LinkByName(attachment.interfaceName); tcLinkNotFound(err) {
				continue
			}
			if err != nil {
				return false, err
			}
			// During a mobile-network handoff the default-interface monitor can
			// briefly report no interface while the old link and its TC filters
			// are still usable. Avoid treating a transient netlink observation as
			// a filter loss and repeatedly tearing down the active attachment.
			continue
		}
		attached, err := attachment.filtersAttached(d.priority)
		if err != nil {
			return false, err
		}
		if !attached {
			return true, nil
		}
	}
	return false, nil
}

type tcAttachmentState struct {
	index   int
	framing commonEBPF.TCLinkFraming
	role    tcInterfaceRole
}

func desiredTCAttachmentState(
	localInterface string,
	sharedInterfaces []string,
	linkByName func(string) (netlink.Link, error),
) (map[string]tcAttachmentState, error) {
	roles := make(map[string]tcInterfaceRole, len(sharedInterfaces)+1)
	if localInterface != "" {
		roles[localInterface] = tcInterfaceRole{local: true}
	}
	for _, interfaceName := range sharedInterfaces {
		role := roles[interfaceName]
		role.shared = true
		roles[interfaceName] = role
	}
	interfaces := make(map[string]tcAttachmentState, len(roles))
	for interfaceName, role := range roles {
		link, err := linkByName(interfaceName)
		if err != nil && tcLinkNotFound(err) {
			continue
		}
		if err != nil {
			return nil, E.Cause(err, "find TC eBPF interface ", interfaceName)
		}
		if link == nil || link.Attrs() == nil {
			return nil, E.New("invalid TC eBPF interface ", interfaceName)
		}
		framing, err := tcLinkFraming(link)
		if err != nil {
			return nil, err
		}
		interfaces[interfaceName] = tcAttachmentState{
			index:   link.Attrs().Index,
			framing: framing,
			role:    role,
		}
	}
	return interfaces, nil
}

func tcAttachmentTopologyChanged(attachments []*tcInterfaceAttachment, desired map[string]tcAttachmentState) bool {
	if len(attachments) != len(desired) {
		return true
	}
	for _, attachment := range attachments {
		state, loaded := desired[attachment.interfaceName]
		if !loaded || state.index != attachment.interfaceIndex ||
			state.framing != attachment.framing || state.role != attachment.role {
			return true
		}
	}
	return false
}
