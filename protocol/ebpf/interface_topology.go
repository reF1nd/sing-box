//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"slices"

	"github.com/sagernet/sing/common/control"

	kernelRuntime "github.com/CHIZI-0618/sing-ebpf/runtime"
)

func (i *Inbound) repairTCInfrastructure() (bool, error) {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return false, nil
	}
	return i.tcDataPlane.RepairInfrastructure()
}

func (i *Inbound) monitoredDefaultInterfaceName() string {
	state := &i.interfaceMonitor
	state.access.Lock()
	defer state.access.Unlock()
	return state.defaultInterfaceName
}

func availableLocalTCInterface(enabled bool, interfaceName string) (string, error) {
	return kernelRuntime.AvailableLocalTCInterface(enabled, interfaceName)
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
	return i.tcDataPlane.AttachmentStateChanged(localInterface, sharedInterfaces)
}

func (i *Inbound) tcAttachmentDescriptions() []string {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.AttachmentDescriptions()
}

func (i *Inbound) updateTCHostAddresses(hostAddresses []netip.Addr) error {
	i.tcDataPlaneAccess.RLock()
	defer i.tcDataPlaneAccess.RUnlock()
	if i.tcDataPlane == nil {
		return nil
	}
	return i.tcDataPlane.UpdateHostAddresses(hostAddresses)
}

func (i *Inbound) updateCgroupHostAddresses(hostAddresses []netip.Addr) error {
	backend := i.cgroupBackendInstance()
	if backend == nil {
		return nil
	}
	return backend.UpdateHostAddresses(hostAddresses)
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
