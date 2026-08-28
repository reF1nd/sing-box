//go:build with_ebpf && (linux || android)

package ebpf

import (
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func (b *CgroupBackend) LoadPrograms(listenerPort uint16) error {
	return b.loadPrograms(listenerPort)
}

func (b *CgroupBackend) loadPrograms(listenerPort uint16) error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return err
	}
	for _, program := range b.runtime.programs {
		if program != nil {
			return eBPFOperationError("load eBPF inbound programs", unix.EALREADY)
		}
	}
	if listenerPort == 0 {
		return E.New("missing eBPF redirect listener port")
	}
	if err := b.updateCgroupControl(listenerPort); err != nil {
		return E.Cause(err, "update cgroup control map")
	}
	programs, err := b.loadCgroupObjectPrograms()
	if err != nil {
		return eBPFBackendOperationError("load eBPF inbound programs", verifierErrorStage(err), err)
	}
	b.runtime.programs = programs
	return nil
}

func (b *CgroupBackend) loadCgroupObjectPrograms() ([]*CiliumEBPF.Program, error) {
	selections := make([]programSelection, 0, cgroupProgramCount)
	slots := make([]int, 0, cgroupProgramCount)
	for slot, definition := range cgroupProgramDefinitions {
		if !b.cgroupProgramEnabled(slot) {
			continue
		}
		selections = append(selections, programSelection{
			section: b.cgroupProgramSection(slot),
			name:    definition.name,
		})
		slots = append(slots, slot)
	}
	loaded, err := loadObjectPrograms(loadCgroup, b.runtime.maps, selections)
	if err != nil {
		return nil, err
	}
	programs := make([]*CiliumEBPF.Program, cgroupProgramCount)
	for index, slot := range slots {
		programs[slot] = loaded[index]
	}
	if err = b.validateCgroupProgramSet(programs); err != nil {
		_ = closePrograms(programs)
		return nil, err
	}
	return programs, nil
}

func (b *CgroupBackend) validateCgroupProgramSet(programs []*CiliumEBPF.Program) error {
	if !b.runtime.enable_udp {
		return nil
	}
	if len(programs) <= cgroupProgramSocketRelease {
		return E.New("incomplete cgroup program set")
	}
	hasSocketRelease := programs[cgroupProgramSocketRelease] != nil
	if hasSocketRelease != b.runtime.socket_release_supported {
		return E.New(
			"inconsistent UDP cleanup program set: socket_release_program=", hasSocketRelease,
			", socket_release_probe=", b.runtime.socket_release_supported,
		)
	}
	return nil
}

func (b *CgroupBackend) cgroupProgramEnabled(slot int) bool {
	enableIPv4 := b.redirectIPv4.IsValid()
	enableIPv6 := b.enableIPv6
	switch slot {
	case cgroupProgramConnect4:
		return enableIPv4
	case cgroupProgramUDP4Sendmsg, cgroupProgramUDP4Recvmsg:
		return enableIPv4 && b.runtime.enable_udp
	case cgroupProgramConnect6:
		return enableIPv4 || enableIPv6
	case cgroupProgramUDP6Sendmsg, cgroupProgramUDP6Recvmsg:
		return (enableIPv4 || enableIPv6) && b.runtime.enable_udp
	case cgroupProgramSocketRelease:
		return b.runtime.enable_udp && b.runtime.socket_release_supported
	default:
		return false
	}
}

func (b *CgroupBackend) cgroupProgramSection(slot int) string {
	protocolSuffix := ""
	if b.runtime.enable_tcp && !b.runtime.enable_udp {
		protocolSuffix = "_tcp"
	} else if !b.runtime.enable_tcp && b.runtime.enable_udp {
		protocolSuffix = "_udp"
	}
	switch slot {
	case cgroupProgramConnect4:
		return "cgroup/connect4_cookie" + protocolSuffix
	case cgroupProgramUDP4Sendmsg:
		return "cgroup/sendmsg4_cookie"
	case cgroupProgramUDP4Recvmsg:
		return "cgroup/recvmsg4"
	case cgroupProgramConnect6:
		if !b.enableIPv6 {
			return "cgroup/connect6_mapped_cookie" + protocolSuffix
		}
		return "cgroup/connect6_cookie" + protocolSuffix
	case cgroupProgramUDP6Sendmsg:
		if !b.enableIPv6 {
			return "cgroup/sendmsg6_mapped_cookie"
		}
		return "cgroup/sendmsg6_cookie"
	case cgroupProgramUDP6Recvmsg:
		if !b.enableIPv6 {
			return "cgroup/recvmsg6_mapped"
		}
		return "cgroup/recvmsg6"
	case cgroupProgramSocketRelease:
		return "cgroup/sock_release_cookie"
	default:
		return ""
	}
}

func (b *CgroupBackend) updateCgroupControl(listenerPort uint16) error {
	var flags uint32
	if b.runtime.enable_tcp {
		flags |= cgroupFlagTCP
	}
	if b.runtime.enable_udp {
		flags |= cgroupFlagUDP
	}
	if b.redirectIPv4.IsValid() {
		flags |= cgroupFlagIPv4
	}
	if b.enableIPv6 {
		flags |= cgroupFlagIPv6
	}
	if b.bypassPrivateAddress {
		flags |= cgroupFlagBypassPrivateAddress
	}
	if b.runtime.uid_policy {
		flags |= cgroupFlagUIDPolicy
	}
	if b.runtime.uid_default_bypass {
		flags |= cgroupFlagUIDDefaultBypass
	}
	if b.runtime.bypass_ipv4_policy {
		flags |= cgroupFlagBypassIPv4
	}
	if b.runtime.bypass_ipv6_policy {
		flags |= cgroupFlagBypassIPv6
	}
	flags |= b.hostAddressFlags()
	if b.runtime.enable_udp && b.runtime.socket_release_supported {
		flags |= cgroupFlagUDPFlow
	}
	if b.fakeIPIPv4.IsValid() {
		flags |= cgroupFlagFakeIPIPv4
	}
	if b.fakeIPIPv6.IsValid() {
		flags |= cgroupFlagFakeIPIPv6
	}
	ipv4Prefix, ipv4HostMask := cgroupIPv4Redirect(b.redirectIPv4)
	control := cgroupControl{
		Flags:                flags,
		UDPTimeoutSeconds:    b.udpTimeoutSeconds,
		DNSMode:              b.dnsMode,
		RedirectIPv4Prefix:   ipv4Prefix,
		RedirectIPv4HostMask: ipv4HostMask,
		ListenerPort:         listenerPort,
	}
	if b.redirectIPv6.IsValid() {
		address := b.redirectIPv6.Addr().As16()
		copy(control.RedirectIPv6Prefix[:], address[:8])
	}
	if b.fakeIPIPv4.IsValid() {
		control.FakeIPIPv4Prefix = b.fakeIPIPv4.Addr().As4()
		control.FakeIPIPv4Mask = prefixMask4(b.fakeIPIPv4.Bits())
	}
	if b.fakeIPIPv6.IsValid() {
		control.FakeIPIPv6Prefix = b.fakeIPIPv6.Addr().As16()
		control.FakeIPIPv6Mask = prefixMask16(b.fakeIPIPv6.Bits())
	}
	key := uint32(0)
	return updateMap(b.runtime.control_map_fd, unsafe.Pointer(&key), unsafe.Pointer(&control))
}

func (b *CgroupBackend) hostAddressFlags() uint32 {
	var flags uint32
	if len(b.hostIPv4) > 0 {
		flags |= cgroupFlagHostIPv4
	}
	if b.enableIPv6 && len(b.hostIPv6) > 0 {
		flags |= cgroupFlagHostIPv6
	}
	return flags
}
