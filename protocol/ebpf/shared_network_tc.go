//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"errors"
	"net"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/netlink"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	tun "github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/x/list"

	"golang.org/x/sys/unix"
)

const (
	sharedNetworkHealthCheckInterval = 2 * time.Minute
	// Run before Android tethering offload (IPv6 priority 2, IPv4 priority 3).
	defaultSharedNetworkTCPriority = 1
	sharedIngressFilterHandle      = 0x5342
	sharedEgressFilterHandle       = 0x5343
)

type sharedTCManager struct {
	backend         *ECommon.SharedNetworkBackend
	prepareBackend  func() (*ECommon.SharedNetworkBackend, error)
	onReady         func()
	logger          sharedNetworkLogger
	interfaces      []string
	enableIPv4      bool
	priority        uint16
	access          sync.Mutex
	attachments     map[string]*sharedTCAttachment
	enabled         bool
	readyNotified   bool
	cancel          context.CancelFunc
	done            chan struct{}
	wake            chan struct{}
	networkMonitor  tun.NetworkUpdateMonitor
	networkCallback *list.Element[tun.NetworkUpdateCallback]
	refreshWarnings warningLimiter
}

type sharedNetworkLogger interface {
	Debug(args ...any)
	Info(args ...any)
	Warn(args ...any)
}

type sharedTCAttachment struct {
	interfaceName        string
	interfaceIndex       int
	interfaceLock        *net.UnixConn
	tcx                  *ECommon.SharedNetworkTCXAttachment
	ingress              *netlink.BpfFilter
	egress               *netlink.BpfFilter
	restoreRouteLocalnet bool
}

func (m *sharedTCManager) Start() error {
	if m.priority == 0 {
		m.priority = defaultSharedNetworkTCPriority
	}
	err := m.reconcile()
	if err != nil {
		return E.Errors(err, m.closeAttachments())
	}
	ctx, cancel := context.WithCancel(context.Background())
	m.cancel = cancel
	m.done = make(chan struct{})
	m.wake = make(chan struct{}, 1)
	if m.networkMonitor != nil {
		m.networkCallback = m.networkMonitor.RegisterCallback(m.Wake)
	}
	go m.loop(ctx)
	return nil
}

func (m *sharedTCManager) loop(ctx context.Context) {
	defer close(m.done)
	ticker := time.NewTicker(sharedNetworkHealthCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		case <-m.wake:
		}
		err := m.reconcile()
		if err != nil {
			m.refreshWarnings.warn(m.logger, "refresh eBPF shared-network interfaces: ", err)
		}
	}
}

func (m *sharedTCManager) Wake() {
	if m == nil || m.wake == nil {
		return
	}
	select {
	case m.wake <- struct{}{}:
	default:
	}
}

func (m *sharedTCManager) reconcile() (err error) {
	defer func() {
		if err == nil {
			return
		}
		m.access.Lock()
		disableErr := m.updateEnabledLocked(false)
		m.access.Unlock()
		if disableErr != nil {
			err = E.Errors(err, E.Cause(disableErr, "disable shared-network after reconciliation failure"))
		}
	}()
	desired := make(map[string]netlink.Link, len(m.interfaces))
	for _, interfaceName := range m.interfaces {
		link, linkErr := netlink.LinkByName(interfaceName)
		if isSharedNetworkLinkNotFound(linkErr) {
			continue
		}
		if linkErr != nil {
			return E.Cause(linkErr, "find shared-network interface ", interfaceName)
		}
		if linkErr = validateSharedNetworkLink(link); linkErr != nil {
			return linkErr
		}
		desired[interfaceName] = link
	}
	if len(desired) == 0 {
		m.access.Lock()
		if len(m.attachments) == 0 {
			err = m.updateEnabledLocked(false)
			m.access.Unlock()
			return err
		}
		m.access.Unlock()
	}
	if m.backend == nil {
		if m.prepareBackend == nil {
			return E.New("missing shared-network eBPF backend initializer")
		}
		m.backend, err = m.prepareBackend()
		if err != nil {
			return E.Cause(err, "initialize shared-network eBPF backend")
		}
		if m.backend == nil {
			return E.New("shared-network eBPF backend initializer returned nil")
		}
	}

	hostAddresses, err := sharedHostAddresses()
	if err != nil {
		return err
	}
	if err = m.backend.UpdateHostAddresses(hostAddresses); err != nil {
		return err
	}

	m.access.Lock()
	var readyCallback func()
	defer func() {
		m.access.Unlock()
		if err == nil && readyCallback != nil {
			readyCallback()
		}
	}()
	for interfaceName, attachment := range m.attachments {
		link, loaded := desired[interfaceName]
		if loaded && link.Attrs().Index == attachment.interfaceIndex {
			repaired, repairErr := repairSharedTCAttachment(
				link,
				attachment,
				m.backend,
				m.enableIPv4,
				m.priority,
			)
			if repairErr != nil {
				return E.Cause(repairErr, "verify shared-network TC attachment on ", interfaceName)
			}
			if repaired {
				m.refreshWarnings.warn(
					m.logger,
					"eBPF shared-network attachment state was externally changed; repaired ", interfaceName,
				)
			}
			continue
		}
		if err = m.detachLocked(attachment); err != nil {
			return E.Cause(err, "detach stale shared-network interface ", interfaceName)
		}
		delete(m.attachments, interfaceName)
	}
	for interfaceName, link := range desired {
		if _, loaded := m.attachments[interfaceName]; loaded {
			continue
		}
		attachment, attachErr := attachSharedTC(link, m.backend, m.enableIPv4, m.priority)
		if attachErr != nil {
			return E.Cause(attachErr, "attach eBPF shared-network to ", interfaceName)
		}
		m.attachments[interfaceName] = attachment
	}
	err = m.updateEnabledLocked(len(m.attachments) > 0)
	if err == nil && len(m.attachments) > 0 && !m.readyNotified {
		m.readyNotified = true
		readyCallback = m.onReady
	}
	return err
}

func (m *sharedTCManager) isEnabled() bool {
	if m == nil {
		return false
	}
	m.access.Lock()
	enabled := m.enabled
	m.access.Unlock()
	return enabled
}

func isSharedNetworkLinkNotFound(err error) bool {
	if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT) {
		return true
	}
	var linkNotFoundError netlink.LinkNotFoundError
	return errors.As(err, &linkNotFoundError)
}

func validateSharedNetworkLink(link netlink.Link) error {
	if link == nil || link.Attrs() == nil {
		return E.New("invalid shared-network interface")
	}
	if len(link.Attrs().HardwareAddr) != 6 {
		return E.New("shared-network interface ", link.Attrs().Name, " is not Ethernet-like")
	}
	return nil
}

func (m *sharedTCManager) updateEnabledLocked(enabled bool) error {
	if m.enabled == enabled {
		return nil
	}
	var err error
	if enabled {
		err = m.backend.Enable()
	} else {
		err = m.backend.Disable()
	}
	if err == nil {
		m.enabled = enabled
	}
	return err
}

func (m *sharedTCManager) detachLocked(attachment *sharedTCAttachment) error {
	if m.backend != nil {
		if _, _, err := m.backend.PurgeInterfaceFlows(
			uint32(attachment.interfaceIndex),
			m.backend.MapCapacity().Proxy,
		); err != nil {
			m.refreshWarnings.warn(m.logger, "purge eBPF shared-network state for ", attachment.interfaceName, ": ", err)
		}
	}
	detachErr := E.Errors(
		attachment.tcx.Close(),
		detachSharedTCFilter(attachment.ingress),
		detachSharedTCFilter(attachment.egress),
	)
	if attachment.restoreRouteLocalnet {
		if err := restoreSharedRouteLocalnet(attachment.interfaceName); err != nil {
			detachErr = E.Errors(detachErr, err)
		} else {
			attachment.restoreRouteLocalnet = false
		}
	}
	if attachment.interfaceLock != nil {
		if err := attachment.interfaceLock.Close(); err != nil {
			detachErr = E.Errors(detachErr, err)
		} else {
			attachment.interfaceLock = nil
		}
	}
	return detachErr
}

func (m *sharedTCManager) InterfaceString() string {
	m.access.Lock()
	defer m.access.Unlock()
	names := make([]string, 0, len(m.attachments))
	for name := range m.attachments {
		names = append(names, name)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "waiting for " + strings.Join(m.interfaces, ", ")
	}
	return strings.Join(names, ", ")
}

func (m *sharedTCManager) AttachmentModeString() string {
	m.access.Lock()
	defer m.access.Unlock()
	if len(m.attachments) == 0 {
		return "waiting"
	}
	tcxCount := 0
	for _, attachment := range m.attachments {
		if attachment.tcx != nil {
			tcxCount++
		}
	}
	if tcxCount == len(m.attachments) {
		return "tcx"
	}
	if tcxCount == 0 {
		return "clsact"
	}
	return "mixed"
}

func (m *sharedTCManager) Close() error {
	if m == nil {
		return nil
	}
	if m.networkCallback != nil {
		m.networkMonitor.UnregisterCallback(m.networkCallback)
		m.networkCallback = nil
	}
	if m.cancel != nil {
		m.cancel()
		<-m.done
		m.cancel = nil
	}
	return m.closeAttachments()
}

func (m *sharedTCManager) closeAttachments() error {
	m.access.Lock()
	defer m.access.Unlock()
	var closeErr error
	if err := m.updateEnabledLocked(false); err != nil {
		closeErr = err
	}
	for name, attachment := range m.attachments {
		if err := m.detachLocked(attachment); err != nil {
			closeErr = E.Errors(closeErr, E.Cause(err, "detach shared-network interface ", name))
			continue
		}
		delete(m.attachments, name)
	}
	return closeErr
}
