//go:build with_ebpf && (linux || android)

package ebpf

func (b *CgroupBackend) CgroupPath() string {
	if b == nil {
		return ""
	}
	return b.cgroupPath
}

func (b *CgroupBackend) AttachedPrograms() []string {
	if b == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return nil
	}
	programs := make([]string, 0, cgroupProgramCount)
	descriptions := [...]string{
		"sb_ebpf_conn4 (cgroup/connect4)",
		"sb_ebpf_udp4 (cgroup/sendmsg4)",
		"sb_ebpf_urcv4 (cgroup/recvmsg4)",
		"sb_ebpf_conn6 (cgroup/connect6)",
		"sb_ebpf_udp6 (cgroup/sendmsg6)",
		"sb_ebpf_urcv6 (cgroup/recvmsg6)",
		"sb_ebpf_rel (cgroup/sock_release)",
	}
	for slot, program := range b.runtime.programs {
		if program != nil {
			programs = append(programs, descriptions[slot])
		}
	}
	return programs
}

func (b *CgroupBackend) UDPCleanupMode() string {
	if b == nil {
		return cgroupUDPCleanupDisabled
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return cgroupUDPCleanupModeLocked(b.runtime)
}

func cgroupUDPCleanupModeLocked(runtimeState *cgroupRuntime) string {
	if runtimeState == nil || !runtimeState.enable_udp {
		return cgroupUDPCleanupDisabled
	}
	if !runtimeState.socket_release_supported {
		return cgroupUDPCleanupLRUFallback
	}
	if len(runtimeState.programs) <= cgroupProgramSocketRelease ||
		runtimeState.programs[cgroupProgramSocketRelease] == nil {
		return cgroupUDPCleanupInvalid
	}
	return cgroupUDPCleanupSocketRelease
}
