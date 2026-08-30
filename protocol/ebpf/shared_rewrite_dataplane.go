//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

const (
	sharedRewriteIngressFilterHandle = 0x5342
	sharedRewriteEgressFilterHandle  = 0x5343
)

type sharedRewriteDataPlane struct {
	access        sync.Mutex
	owner         *sharedRewrite
	backend       *commonEBPF.SharedNetworkBackend
	attachments   map[string]*sharedRewriteAttachment
	hostAddresses []netip.Addr
	priority      uint16
	enabled       bool
	ready         bool
}

type sharedRewriteAttachment struct {
	interfaceName   string
	interfaceIndex  int
	lock            io.Closer
	ingressFilter   *netlink.BpfFilter
	egressFilter    *netlink.BpfFilter
	ingressLink     link.Link
	egressLink      link.Link
	restoreLocalnet bool
	attachmentType  string
}

func newSharedRewriteDataPlane(owner *sharedRewrite, priority uint16) *sharedRewriteDataPlane {
	return &sharedRewriteDataPlane{
		owner:       owner,
		attachments: make(map[string]*sharedRewriteAttachment),
		priority:    priority,
	}
}

func (d *sharedRewriteDataPlane) reconcile(interfaceNames []string, hostAddresses []netip.Addr) error {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()

	desired := make(map[string]netlink.Link, len(interfaceNames))
	for _, interfaceName := range interfaceNames {
		device, err := netlink.LinkByName(interfaceName)
		if tcLinkNotFound(err) {
			continue
		}
		if err != nil {
			return E.Cause(err, "find shared packet-rewrite interface ", interfaceName)
		}
		framing, err := tcLinkFraming(device)
		if err != nil {
			return err
		}
		if framing != commonEBPF.TCLinkFramingEthernet {
			return E.New("shared packet-rewrite interface ", interfaceName, " must use Ethernet framing")
		}
		desired[interfaceName] = device
	}

	if len(desired) > 0 && d.backend == nil {
		backend, err := d.owner.prepareBackend()
		if err != nil {
			return E.Cause(err, "initialize shared packet-rewrite backend")
		}
		d.backend = backend
	}
	if d.backend != nil && !slices.Equal(d.hostAddresses, hostAddresses) {
		if err := d.backend.UpdateHostAddresses(hostAddresses); err != nil {
			return E.Cause(err, "update shared packet-rewrite host addresses")
		}
		d.hostAddresses = slices.Clone(hostAddresses)
	}

	changed := false
	for name, attachment := range d.attachments {
		device, keep := desired[name]
		if keep && device.Attrs().Index == attachment.interfaceIndex {
			localnetChanged, err := ensureSharedRewriteLocalnet(name)
			if err != nil {
				return E.Cause(err, "repair route_localnet for ", name)
			}
			if localnetChanged {
				attachment.restoreLocalnet = true
			}
			healthy, err := attachment.healthy(device, d.priority)
			if err != nil {
				return E.Cause(err, "inspect shared packet-rewrite attachment on ", name)
			}
			if healthy {
				delete(desired, name)
				continue
			}
		}
		if err := d.detachLocked(attachment); err != nil {
			return E.Cause(err, "detach shared packet-rewrite interface ", name)
		}
		delete(d.attachments, name)
		changed = true
	}
	var added []string
	for name, device := range desired {
		attachment, err := attachSharedRewriteInterface(device, d.backend, d.priority)
		if err != nil {
			rollbackErr := error(nil)
			for index := len(added) - 1; index >= 0; index-- {
				addedName := added[index]
				rollbackErr = E.Errors(rollbackErr, d.detachLocked(d.attachments[addedName]))
				delete(d.attachments, addedName)
			}
			if rollbackErr != nil {
				rollbackErr = E.Cause(rollbackErr, "rollback new shared packet-rewrite attachments")
			}
			return E.Errors(E.Cause(err, "attach shared packet-rewrite interface ", name), rollbackErr)
		}
		d.attachments[name] = attachment
		added = append(added, name)
		changed = true
	}

	wantEnabled := len(d.attachments) > 0
	if wantEnabled != d.enabled {
		var err error
		if wantEnabled {
			err = d.backend.Enable()
		} else if d.backend != nil {
			err = d.backend.Disable()
		}
		if err != nil {
			return err
		}
		d.enabled = wantEnabled
		changed = true
	}
	if changed {
		d.owner.udpNat.Purge()
	}
	if d.enabled && !d.ready {
		d.ready = true
		d.owner.sharedRewriteReadyLocked(d.attachmentDescriptionsLocked())
	}
	return nil
}

func (d *sharedRewriteDataPlane) detachLocked(attachment *sharedRewriteAttachment) error {
	if d.backend != nil {
		if _, _, err := d.backend.PurgeInterfaceFlows(uint32(attachment.interfaceIndex), d.backend.MapCapacity().Proxy); err != nil {
			d.owner.janitorWarnings.warn(d.owner.inbound.logger, "purge shared packet-rewrite state for ", attachment.interfaceName, ": ", err)
		}
	}
	return attachment.Close()
}

func (d *sharedRewriteDataPlane) isEnabled() bool {
	if d == nil {
		return false
	}
	d.access.Lock()
	defer d.access.Unlock()
	return d.enabled
}

func (d *sharedRewriteDataPlane) attachmentDescriptions() []string {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	return d.attachmentDescriptionsLocked()
}

func (d *sharedRewriteDataPlane) attachmentDescriptionsLocked() []string {
	descriptions := make([]string, 0, len(d.attachments))
	for _, attachment := range d.attachments {
		descriptions = append(descriptions, attachment.interfaceName+"("+attachment.attachmentType+")")
	}
	slices.Sort(descriptions)
	return descriptions
}

func (d *sharedRewriteDataPlane) Close() error {
	if d == nil {
		return nil
	}
	d.access.Lock()
	defer d.access.Unlock()
	var closeErr error
	if d.enabled && d.backend != nil {
		closeErr = d.backend.Disable()
		d.enabled = false
	}
	for name, attachment := range d.attachments {
		closeErr = E.Errors(closeErr, d.detachLocked(attachment))
		delete(d.attachments, name)
	}
	return closeErr
}

func attachSharedRewriteInterface(
	device netlink.Link,
	backend *commonEBPF.SharedNetworkBackend,
	priority uint16,
) (*sharedRewriteAttachment, error) {
	name := device.Attrs().Name
	attachment := &sharedRewriteAttachment{interfaceName: name, interfaceIndex: device.Attrs().Index}
	cleanup := func(err error) (*sharedRewriteAttachment, error) {
		return nil, E.Errors(err, attachment.Close())
	}
	interfaceLock, err := acquireTCInterfaceLock(name, device.Attrs().Index)
	if err != nil {
		return nil, err
	}
	attachment.lock = interfaceLock
	attachment.restoreLocalnet, err = enableSharedRewriteLocalnet(name)
	if err != nil {
		return cleanup(err)
	}
	if priority == defaultTCPriority && tcxSupport.Load() != tcxSupportUnavailable {
		attachment.egressLink, err = link.AttachTCX(link.TCXOptions{
			Interface: device.Attrs().Index,
			Program:   backend.EgressProgram(),
			Attach:    CiliumEBPF.AttachTCXEgress,
		})
		if err == nil {
			attachment.ingressLink, err = link.AttachTCX(link.TCXOptions{
				Interface: device.Attrs().Index,
				Program:   backend.IngressProgram(),
				Attach:    CiliumEBPF.AttachTCXIngress,
			})
		}
		if err == nil {
			tcxSupport.Store(tcxSupportAvailable)
			attachment.attachmentType = "tcx"
			return attachment, nil
		}
		_ = attachment.closeLinks()
		if !tcxUnsupportedError(err) {
			return cleanup(err)
		}
		tcxSupport.CompareAndSwap(tcxSupportUnknown, tcxSupportUnavailable)
	}
	if err = ensureTCClsact(device); err != nil {
		return cleanup(err)
	}
	attachment.egressFilter, err = attachTCFilter(device, netlink.HANDLE_MIN_EGRESS, backend.EgressProgramFD(), "sb_share_out", sharedRewriteEgressFilterHandle, priority)
	if err != nil {
		return cleanup(err)
	}
	attachment.ingressFilter, err = attachTCFilter(device, netlink.HANDLE_MIN_INGRESS, backend.IngressProgramFD(), "sb_share_in", sharedRewriteIngressFilterHandle, priority)
	if err != nil {
		return cleanup(err)
	}
	attachment.attachmentType = "clsact"
	return attachment, nil
}

func (a *sharedRewriteAttachment) healthy(device netlink.Link, priority uint16) (bool, error) {
	if a.ingressLink != nil || a.egressLink != nil {
		ingress, err := tcxLinkAttached(a.ingressLink, a.interfaceIndex, CiliumEBPF.AttachTCXIngress)
		if err != nil || !ingress {
			return false, err
		}
		return tcxLinkAttached(a.egressLink, a.interfaceIndex, CiliumEBPF.AttachTCXEgress)
	}
	ingress, err := tcFilterAttached(device, netlink.HANDLE_MIN_INGRESS, "sb_share_in", sharedRewriteIngressFilterHandle, priority)
	if err != nil || !ingress {
		return false, err
	}
	return tcFilterAttached(device, netlink.HANDLE_MIN_EGRESS, "sb_share_out", sharedRewriteEgressFilterHandle, priority)
}

func (a *sharedRewriteAttachment) closeLinks() error {
	var closeErr error
	if a.ingressLink != nil {
		closeErr = a.ingressLink.Close()
		a.ingressLink = nil
	}
	if a.egressLink != nil {
		closeErr = E.Errors(closeErr, a.egressLink.Close())
		a.egressLink = nil
	}
	return closeErr
}

func (a *sharedRewriteAttachment) Close() error {
	if a == nil {
		return nil
	}
	closeErr := E.Errors(a.closeLinks(), detachTCFilter(a.ingressFilter), detachTCFilter(a.egressFilter))
	a.ingressFilter = nil
	a.egressFilter = nil
	if a.restoreLocalnet {
		closeErr = E.Errors(closeErr, restoreSharedRewriteLocalnet(a.interfaceName))
		a.restoreLocalnet = false
	}
	if a.lock != nil {
		closeErr = E.Errors(closeErr, a.lock.Close())
		a.lock = nil
	}
	return closeErr
}

func sharedRewriteLocalnetPath(interfaceName string) string {
	return "/proc/sys/net/ipv4/conf/" + interfaceName + "/route_localnet"
}

func enableSharedRewriteLocalnet(interfaceName string) (bool, error) {
	return ensureSharedRewriteLocalnet(interfaceName)
}

func ensureSharedRewriteLocalnet(interfaceName string) (bool, error) {
	value, err := os.ReadFile(sharedRewriteLocalnetPath(interfaceName))
	if err != nil {
		return false, E.Cause(err, "read route_localnet for ", interfaceName)
	}
	switch strings.TrimSpace(string(value)) {
	case "1":
		return false, nil
	case "0":
		if err = os.WriteFile(sharedRewriteLocalnetPath(interfaceName), []byte("1"), 0o644); err != nil {
			return false, E.Cause(err, "enable route_localnet for ", interfaceName)
		}
		return true, nil
	default:
		return false, E.New("unexpected route_localnet value for ", interfaceName)
	}
}

func restoreSharedRewriteLocalnet(interfaceName string) error {
	path := sharedRewriteLocalnetPath(interfaceName)
	value, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "read route_localnet for ", interfaceName)
	}
	if strings.TrimSpace(string(value)) != "1" {
		return nil
	}
	if err = os.WriteFile(path, []byte("0"), 0o644); err != nil {
		return E.Cause(err, "restore route_localnet for ", interfaceName)
	}
	return nil
}
