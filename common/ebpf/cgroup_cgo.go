//go:build with_ebpf && (linux || android) && cgo

package ebpf

/*
#cgo CFLAGS: -I${SRCDIR}/native
#include <errno.h>
#include <stdlib.h>
#include "ebpf.h"

static int singbox_ebpf_cgroup_prepare(
	const char *cgroup_path,
	bool enable_tcp,
	bool enable_udp,
	bool enable_bypass_ipv4_cidr,
	bool enable_bypass_ipv6_cidr,
	uint32_t include_uid_entries,
	uint32_t exclude_uid_entries,
	uint32_t tcp_redirect_map_capacity,
	uint32_t udp_redirect_map_capacity,
	uint32_t socket_bypass_map_capacity,
	struct sb_ebpf_cgroup_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_cgroup_prepare(
		cgroup_path,
		enable_tcp,
		enable_udp,
		enable_bypass_ipv4_cidr,
		enable_bypass_ipv6_cidr,
		include_uid_entries,
		exclude_uid_entries,
		tcp_redirect_map_capacity,
		udp_redirect_map_capacity,
		socket_bypass_map_capacity,
		runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_cgroup_load_programs(
	struct sb_ebpf_cgroup_runtime *runtime,
	uint16_t listen_port,
	uint32_t self_tgid,
	bool enable_ipv4,
	bool hijack_dns,
	const uint8_t *redirect_ipv4,
	uint32_t redirect_ipv4_prefix_bits,
	bool enable_ipv6,
	const uint8_t *redirect_ipv6,
	uint32_t redirect_ipv6_prefix_bits,
	int *saved_errno) {
	int result = sb_ebpf_cgroup_load_programs(
		runtime,
		listen_port,
		self_tgid,
		enable_ipv4,
		hijack_dns,
		redirect_ipv4,
		redirect_ipv4_prefix_bits,
		enable_ipv6,
		redirect_ipv6,
		redirect_ipv6_prefix_bits);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_cgroup_attach(
	struct sb_ebpf_cgroup_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_cgroup_attach(runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_cgroup_close(
	struct sb_ebpf_cgroup_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_cgroup_close(runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}
*/
import "C"

import (
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

type CgroupBackend struct {
	access              sync.RWMutex
	lookupAndDeleteMode atomic.Int32
	runtime             *C.struct_sb_ebpf_cgroup_runtime
	tcpRedirectMapFD    int
	udpRedirectMapFD    int
	udpFlowMapFD        int
	socketBypassMapFD   int
	bypassIPv4CIDRMapFD int
	bypassIPv6CIDRMapFD int
	bypassIPv4CIDR      []netip.Prefix
	bypassIPv6CIDR      []netip.Prefix
	cgroupPath          string
	redirectIPv4        netip.Prefix
	redirectIPv6        netip.Prefix
	enableUDP           bool
	hijackDNS           bool
}

func PrepareCgroup(config CgroupConfig) (*CgroupBackend, error) {
	cgroupPath := config.Path
	redirectIPv4 := config.RedirectIPv4
	redirectIPv6 := config.RedirectIPv6
	mapCapacity := config.MapCapacity
	policy := config.Policy
	if err := validateMapCapacity(mapCapacity); err != nil {
		return nil, err
	}
	if redirectIPv4.IsValid() {
		redirectIPv4 = redirectIPv4.Masked()
		if !redirectIPv4.Addr().Is4() {
			return nil, E.New("invalid IPv4 eBPF redirect address: ", redirectIPv4)
		}
		if err := ValidateRedirectPrefix(redirectIPv4); err != nil {
			return nil, err
		}
	}
	if redirectIPv6.IsValid() {
		redirectIPv6 = redirectIPv6.Masked()
		if !redirectIPv6.Addr().Is6() || redirectIPv6.Addr().Is4In6() {
			return nil, E.New("invalid IPv6 eBPF redirect address: ", redirectIPv6)
		}
		if err := ValidateRedirectPrefix(redirectIPv6); err != nil {
			return nil, err
		}
	}
	if !redirectIPv4.IsValid() && !redirectIPv6.IsValid() {
		return nil, E.New("missing eBPF redirect address")
	}
	includeUIDEntries, err := compileUIDPolicy("include_uid", policy.IncludeUID)
	if err != nil {
		return nil, err
	}
	excludeUIDEntries, err := compileUIDPolicy("exclude_uid", policy.ExcludeUID)
	if err != nil {
		return nil, err
	}
	if cgroupPath == "" {
		cgroupPath, err = DetectCgroup2Mount()
		if err != nil {
			return nil, err
		}
	}
	memlockErr := raiseMemlockLimit()
	if err := checkKernelCapabilities(cgroupPath); err != nil {
		if memlockErr != nil {
			return nil, E.Errors(err, E.Cause(memlockErr, "remove memlock limit"))
		}
		return nil, err
	}
	runtimeState := (*C.struct_sb_ebpf_cgroup_runtime)(C.calloc(1, C.size_t(C.sizeof_struct_sb_ebpf_cgroup_runtime)))
	if runtimeState == nil {
		return nil, E.New("allocate eBPF runtime")
	}
	var cgroupPathCString *C.char
	if cgroupPath != "" {
		cgroupPathCString = C.CString(cgroupPath)
		defer C.free(unsafe.Pointer(cgroupPathCString))
	}
	var savedErrno C.int
	if C.singbox_ebpf_cgroup_prepare(
		cgroupPathCString,
		C.bool(config.EnableTCP),
		C.bool(config.EnableUDP),
		C.bool(policy.EnableBypassCIDR && redirectIPv4.IsValid()),
		C.bool(policy.EnableBypassCIDR && redirectIPv6.IsValid()),
		C.uint32_t(len(includeUIDEntries)),
		C.uint32_t(len(excludeUIDEntries)),
		C.uint32_t(mapCapacity.TCPRedirect),
		C.uint32_t(mapCapacity.UDPRedirect),
		C.uint32_t(mapCapacity.SocketBypass),
		runtimeState,
		&savedErrno,
	) != 0 {
		prepareErrno := syscall.Errno(savedErrno)
		var prepareErr error = prepareErrno
		if memlockErr != nil && (prepareErrno == unix.ENOMEM || prepareErrno == unix.EPERM) {
			prepareErr = E.Cause(prepareErr, "memlock limit could not be removed: ", memlockErr)
		}
		C.free(unsafe.Pointer(runtimeState))
		return nil, eBPFOperationError("prepare eBPF inbound", prepareErr)
	}
	backend := &CgroupBackend{
		runtime:             runtimeState,
		tcpRedirectMapFD:    int(runtimeState.tcp_redirect_map_fd),
		udpRedirectMapFD:    int(runtimeState.udp_redirect_map_fd),
		udpFlowMapFD:        int(runtimeState.udp_flow_map_fd),
		socketBypassMapFD:   int(runtimeState.bypass_socket_cookie_map_fd),
		bypassIPv4CIDRMapFD: int(runtimeState.bypass_ipv4_cidr_map_fd),
		bypassIPv6CIDRMapFD: int(runtimeState.bypass_ipv6_cidr_map_fd),
		cgroupPath:          cgroupPath,
		redirectIPv4:        redirectIPv4,
		redirectIPv6:        redirectIPv6,
		enableUDP:           config.EnableUDP,
		hijackDNS:           policy.HijackDNS,
	}
	if err = populateUIDPolicyMap(int(runtimeState.include_uid_map_fd), includeUIDEntries); err != nil {
		_ = backend.Close()
		return nil, E.Cause(err, "populate include_uid eBPF map")
	}
	if err = populateUIDPolicyMap(int(runtimeState.exclude_uid_map_fd), excludeUIDEntries); err != nil {
		_ = backend.Close()
		return nil, E.Cause(err, "populate exclude_uid eBPF map")
	}
	return backend, nil
}

func raiseMemlockLimit() error {
	unlimited := unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	unlimitedErr := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unlimited)
	if unlimitedErr == nil {
		return nil
	}

	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
		return E.Errors(unlimitedErr, E.Cause(err, "read memlock limit"))
	}
	if limit.Cur < limit.Max {
		limit.Cur = limit.Max
		if err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &limit); err != nil {
			return E.Errors(unlimitedErr, E.Cause(err, "raise soft memlock limit"))
		}
	}
	return unlimitedErr
}

func checkKernelCapabilities(cgroupPath string) error {
	var fileSystem unix.Statfs_t
	if err := unix.Statfs(cgroupPath, &fileSystem); err != nil {
		return E.Cause(err, "check eBPF cgroup2 mount")
	}
	if fileSystem.Type != unix.CGROUP2_SUPER_MAGIC {
		return E.New("eBPF inbound is not supported: ", cgroupPath, " is not a cgroup2 mount")
	}

	attribute := mapCreateAttr{
		MapType:    bpfMapTypeArray,
		KeySize:    4,
		ValueSize:  4,
		MaxEntries: 1,
	}
	fd, _, errno := unix.Syscall(
		unix.SYS_BPF,
		bpfMapCreate,
		uintptr(unsafe.Pointer(&attribute)),
		unsafe.Sizeof(attribute),
	)
	if errno != 0 {
		return eBPFOperationError("probe BPF_MAP_CREATE", errno)
	}
	if err := unix.Close(int(fd)); err != nil {
		return E.Cause(err, "close eBPF capability probe map")
	}
	return nil
}

func eBPFOperationError(operation string, err error) error {
	if errno, isErrno := err.(syscall.Errno); isErrno {
		switch errno {
		case unix.EBUSY:
			return E.Cause(errno, "another eBPF inbound is already active on this cgroup: ", operation)
		case unix.ENOSYS, unix.EINVAL, unix.EOPNOTSUPP:
			return E.Cause(errno, "eBPF inbound is not supported by this kernel: ", operation)
		case unix.EPERM, unix.EACCES:
			return E.Cause(errno, "eBPF inbound is not permitted on this device: ", operation)
		}
	}
	return E.Cause(err, operation)
}

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
	programs := make([]string, 0, 10)
	if b.runtime.connect4_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_conn4 (cgroup/connect4)")
	}
	if b.enableUDP && b.runtime.udp4_sendmsg_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_udp4 (cgroup/sendmsg4)")
	}
	if b.enableUDP && b.runtime.udp4_recvmsg_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_urcv4 (cgroup/recvmsg4)")
	}
	if b.runtime.connect6_v4mapped_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_c6v4m (cgroup/connect6)")
	}
	if b.runtime.connect6_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_conn6 (cgroup/connect6)")
	}
	if b.enableUDP && b.runtime.udp6_v4mapped_sendmsg_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_u6v4m (cgroup/sendmsg6)")
	}
	if b.enableUDP && b.runtime.udp6_sendmsg_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_udp6 (cgroup/sendmsg6)")
	}
	if b.enableUDP && b.runtime.udp6_v4mapped_recvmsg_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_ur6v4m (cgroup/recvmsg6)")
	}
	if b.enableUDP && b.runtime.udp6_recvmsg_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_urcv6 (cgroup/recvmsg6)")
	}
	if b.enableUDP && b.runtime.socket_release_prog_fd >= 0 {
		programs = append(programs, "sb_ebpf_rel (cgroup/sock_release)")
	}
	return programs
}

func (b *CgroupBackend) UsesSocketRelease() bool {
	if b == nil {
		return false
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime != nil && b.runtime.socket_release_prog_fd >= 0
}

func (b *CgroupBackend) LoadPrograms(listenerPort uint16) error {
	return b.loadPrograms(listenerPort, uint32(os.Getpid()))
}

func (b *CgroupBackend) loadPrograms(listenerPort uint16, selfTGID uint32) error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	var redirectIPv4Bytes [4]byte
	var redirectIPv4Pointer *C.uint8_t
	var redirectIPv4Bits C.uint32_t
	if b.redirectIPv4.IsValid() {
		redirectIPv4Bytes = b.redirectIPv4.Addr().As4()
		redirectIPv4Pointer = (*C.uint8_t)(unsafe.Pointer(&redirectIPv4Bytes[0]))
		redirectIPv4Bits = C.uint32_t(b.redirectIPv4.Bits())
	}
	var redirectIPv6Bytes [16]byte
	var redirectIPv6Pointer *C.uint8_t
	var redirectIPv6Bits C.uint32_t
	if b.redirectIPv6.IsValid() {
		redirectIPv6Bytes = b.redirectIPv6.Addr().As16()
		redirectIPv6Pointer = (*C.uint8_t)(unsafe.Pointer(&redirectIPv6Bytes[0]))
		redirectIPv6Bits = C.uint32_t(b.redirectIPv6.Bits())
	}
	var savedErrno C.int
	if C.singbox_ebpf_cgroup_load_programs(
		b.runtime,
		C.uint16_t(listenerPort),
		C.uint32_t(selfTGID),
		C.bool(b.redirectIPv4.IsValid()),
		C.bool(b.hijackDNS),
		redirectIPv4Pointer,
		redirectIPv4Bits,
		C.bool(b.redirectIPv6.IsValid()),
		redirectIPv6Pointer,
		redirectIPv6Bits,
		&savedErrno,
	) != 0 {
		return eBPFOperationError("load eBPF inbound programs", syscall.Errno(savedErrno))
	}
	return nil
}

func (b *CgroupBackend) SelfBypassMode() string {
	if b == nil {
		return ""
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return ""
	}
	if b.runtime.self_bypass_tgid {
		return "tgid"
	}
	return "socket_cookie"
}

func (b *CgroupBackend) Attach() error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	var savedErrno C.int
	if C.singbox_ebpf_cgroup_attach(b.runtime, &savedErrno) != 0 {
		return eBPFOperationError("attach eBPF inbound", syscall.Errno(savedErrno))
	}
	return nil
}

func (b *CgroupBackend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	var savedErrno C.int
	result := C.singbox_ebpf_cgroup_close(b.runtime, &savedErrno)
	if b.runtime.cgroup_fd < 0 && b.runtime.attached_programs == 0 {
		C.free(unsafe.Pointer(b.runtime))
		b.runtime = nil
		b.tcpRedirectMapFD = -1
		b.udpRedirectMapFD = -1
		b.socketBypassMapFD = -1
		b.bypassIPv4CIDRMapFD = -1
		b.bypassIPv6CIDRMapFD = -1
		b.bypassIPv4CIDR = nil
		b.bypassIPv6CIDR = nil
	}
	if result != 0 {
		return E.Cause(syscall.Errno(savedErrno), "close eBPF inbound")
	}
	return nil
}

func (b *CgroupBackend) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime == nil
}
