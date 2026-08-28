//go:build with_ebpf && (linux || android)

package ebpf

import E "github.com/sagernet/sing/common/exceptions"

func (b *CgroupBackend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	if err := b.detachProgramsLocked(); err != nil {
		return E.Cause(err, "detach eBPF inbound")
	}
	closeErr := closePrograms(b.runtime.programs)
	closeErr = E.Errors(closeErr, closeMaps(b.runtime.maps))
	if b.runtime.cgroupFile != nil {
		closeErr = E.Errors(closeErr, b.runtime.cgroupFile.Close())
	}
	b.runtime = nil
	b.tcpRedirectMapFD = -1
	b.udpRedirectMapFD = -1
	b.udpRecoveryMapFD = -1
	b.udpFlowMapFD = -1
	b.socketBypassMapFD = -1
	b.bypassIPv4CIDRMapFD = -1
	b.bypassIPv6CIDRMapFD = -1
	b.hostIPv4MapFD = -1
	b.hostIPv6MapFD = -1
	b.bypassIPv4CIDR = nil
	b.bypassIPv6CIDR = nil
	b.hostIPv4 = nil
	b.hostIPv6 = nil
	return closeErr
}

func (b *CgroupBackend) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime == nil
}
