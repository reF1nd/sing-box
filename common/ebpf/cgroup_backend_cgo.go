//go:build with_ebpf && (linux || android) && cgo

package ebpf

/*
#cgo CFLAGS: -I${SRCDIR}/native
#include <errno.h>
#include <stdlib.h>
#include "runtime.h"

static int singbox_ebpf_cgroup_prepare(
	const char *cgroup_path,
	bool enable_tcp,
	bool enable_udp,
	bool enable_bypass_ipv4_cidr,
	bool enable_bypass_ipv6_cidr,
	bool auto_ipv6,
	uint32_t uid_policy_entries,
	bool uid_default_bypass,
	bool exclude_android_dns_tether,
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
		auto_ipv6,
		uid_policy_entries,
		uid_default_bypass,
		exclude_android_dns_tether,
		tcp_redirect_map_capacity,
		udp_redirect_map_capacity,
		socket_bypass_map_capacity,
		runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_cgroup_load_programs(
	struct sb_ebpf_cgroup_runtime *runtime,
	const uint8_t *object,
	size_t object_size,
	uint16_t listen_port,
	uint32_t self_tgid,
	bool enable_ipv4,
	bool hijack_dns,
	uint32_t udp_timeout_seconds,
	const uint8_t *redirect_ipv4,
	uint32_t redirect_ipv4_prefix_bits,
	bool enable_ipv6,
	const uint8_t *redirect_ipv6,
	uint32_t redirect_ipv6_prefix_bits,
	int *saved_errno) {
	int result = sb_ebpf_cgroup_load_programs(
		runtime,
		object,
		object_size,
		listen_port,
		self_tgid,
		enable_ipv4,
		hijack_dns,
		udp_timeout_seconds,
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

static int singbox_ebpf_cgroup_probe_self_tgid(
	struct sb_ebpf_cgroup_runtime *runtime,
	uint32_t *self_tgid,
	int *saved_errno) {
	int result = sb_ebpf_cgroup_probe_self_tgid(runtime, self_tgid);
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

static const char *singbox_ebpf_cgroup_error_stage(
	const struct sb_ebpf_cgroup_runtime *runtime) {
	return runtime == NULL ? NULL : runtime->error_stage;
}

static int singbox_ebpf_cgroup_program_fd(
	const struct sb_ebpf_cgroup_runtime *runtime,
	enum sb_ebpf_cgroup_program_slot slot) {
	if (runtime == NULL || slot < 0 || slot >= SB_EBPF_CGROUP_PROGRAM_COUNT) return -1;
	return runtime->program_fds[slot];
}
*/
import "C"

import (
	_ "embed"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

//go:embed native/cgroup.bpf.o
var cgroupObject []byte

type CgroupBackend struct {
	access               sync.RWMutex
	health               backendHealth
	lookupAndDeleteMode  atomic.Int32
	runtime              *C.struct_sb_ebpf_cgroup_runtime
	tcpRedirectMapFD     int
	udpRedirectMapFD     int
	udpFlowMapFD         int
	socketBypassMapFD    int
	pendingSocketCookies map[uint64]struct{}
	bypassIPv4CIDRMapFD  int
	bypassIPv6CIDRMapFD  int
	ipv6AvailableMapFD   int
	bypassIPv4CIDR       []netip.Prefix
	bypassIPv6CIDR       []netip.Prefix
	cgroupPath           string
	redirectIPv4         netip.Prefix
	redirectIPv6         netip.Prefix
	enableIPv6           bool
	autoIPv6             bool
	ipv6Available        bool
	enableUDP            bool
	hijackDNS            bool
	udpTimeoutSeconds    uint32
}

func PrepareCgroup(config CgroupConfig) (*CgroupBackend, error) {
	cgroupPath := config.Path
	redirectIPv4 := config.RedirectIPv4
	redirectIPv6 := config.RedirectIPv6
	mapCapacity := config.MapCapacity
	policy := config.Policy
	if err := validateCgroupMapCapacity(mapCapacity); err != nil {
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
	if config.EnableIPv6 && !redirectIPv6.IsValid() {
		return nil, E.New("missing IPv6 eBPF redirect address")
	}
	if config.AutoIPv6 && !config.EnableIPv6 {
		return nil, E.New("automatic IPv6 interception requires enabled IPv6 interception")
	}
	if !redirectIPv4.IsValid() && !config.EnableIPv6 {
		return nil, E.New("eBPF cgroup backend has no enabled address family")
	}
	udpTimeoutSeconds := uint32(0)
	var err error
	if config.EnableUDP {
		udpTimeoutSeconds, err = cgroupUDPTimeoutSeconds(config.UDPTimeout)
		if err != nil {
			return nil, err
		}
	}
	uidPolicyEntries, uidDefaultBypass, err := compileUIDPolicy(policy)
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
	if err := checkKernelCapabilities("cgroup", cgroupPath); err != nil {
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
		C.bool(config.AutoIPv6),
		C.uint32_t(len(uidPolicyEntries)),
		C.bool(uidDefaultBypass),
		C.bool(policy.ExcludeAndroidDNSTether),
		C.uint32_t(mapCapacity.TCPRedirect),
		C.uint32_t(mapCapacity.UDPRedirect),
		C.uint32_t(mapCapacity.SocketBypass),
		runtimeState,
		&savedErrno,
	) != 0 {
		prepareErrno := syscall.Errno(savedErrno)
		errorStage := C.GoString(C.singbox_ebpf_cgroup_error_stage(runtimeState))
		var prepareErr error = prepareErrno
		if memlockErr != nil && (prepareErrno == unix.ENOMEM || prepareErrno == unix.EPERM) {
			prepareErr = E.Cause(prepareErr, "memlock limit could not be removed: ", memlockErr)
		}
		C.free(unsafe.Pointer(runtimeState))
		return nil, eBPFBackendOperationError("prepare eBPF inbound", errorStage, prepareErr)
	}
	backend := &CgroupBackend{
		runtime:             runtimeState,
		tcpRedirectMapFD:    int(runtimeState.tcp_redirect_map_fd),
		udpRedirectMapFD:    int(runtimeState.udp_redirect_map_fd),
		udpFlowMapFD:        int(runtimeState.udp_flow_map_fd),
		socketBypassMapFD:   int(runtimeState.bypass_socket_cookie_map_fd),
		bypassIPv4CIDRMapFD: int(runtimeState.bypass_ipv4_cidr_map_fd),
		bypassIPv6CIDRMapFD: int(runtimeState.bypass_ipv6_cidr_map_fd),
		ipv6AvailableMapFD:  int(runtimeState.ipv6_available_map_fd),
		cgroupPath:          cgroupPath,
		redirectIPv4:        redirectIPv4,
		redirectIPv6:        redirectIPv6,
		enableIPv6:          config.EnableIPv6,
		autoIPv6:            config.AutoIPv6,
		ipv6Available:       false,
		enableUDP:           config.EnableUDP,
		hijackDNS:           policy.HijackDNS,
		udpTimeoutSeconds:   udpTimeoutSeconds,
	}
	if config.AutoIPv6 {
		if _, err = backend.updateIPv6AvailableLocked(config.IPv6Available); err != nil {
			_ = backend.Close()
			return nil, E.Cause(err, "initialize IPv6 availability eBPF map")
		}
	}
	if err = populateUIDPolicyMap(int(runtimeState.uid_policy_map_fd), uidPolicyEntries); err != nil {
		_ = backend.Close()
		return nil, E.Cause(err, "populate UID policy eBPF map")
	}
	return backend, nil
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
	programs := make([]string, 0, int(C.SB_EBPF_CGROUP_PROGRAM_COUNT))
	for _, program := range []struct {
		slot C.enum_sb_ebpf_cgroup_program_slot
		name string
	}{
		{C.SB_EBPF_CGROUP_PROGRAM_CONNECT4, "sb_ebpf_conn4 (cgroup/connect4)"},
		{C.SB_EBPF_CGROUP_PROGRAM_UDP4_SENDMSG, "sb_ebpf_udp4 (cgroup/sendmsg4)"},
		{C.SB_EBPF_CGROUP_PROGRAM_UDP4_RECVMSG, "sb_ebpf_urcv4 (cgroup/recvmsg4)"},
		{C.SB_EBPF_CGROUP_PROGRAM_CONNECT6, "sb_ebpf_conn6 (cgroup/connect6)"},
		{C.SB_EBPF_CGROUP_PROGRAM_UDP6_SENDMSG, "sb_ebpf_udp6 (cgroup/sendmsg6)"},
		{C.SB_EBPF_CGROUP_PROGRAM_UDP6_RECVMSG, "sb_ebpf_urcv6 (cgroup/recvmsg6)"},
		{C.SB_EBPF_CGROUP_PROGRAM_SOCKET_RELEASE, "sb_ebpf_rel (cgroup/sock_release)"},
	} {
		if C.singbox_ebpf_cgroup_program_fd(b.runtime, program.slot) >= 0 {
			programs = append(programs, program.name)
		}
	}
	return programs
}

func (b *CgroupBackend) UsesSocketRelease() bool {
	if b == nil {
		return false
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime != nil && C.singbox_ebpf_cgroup_program_fd(
		b.runtime,
		C.SB_EBPF_CGROUP_PROGRAM_SOCKET_RELEASE,
	) >= 0
}

func (b *CgroupBackend) LoadPrograms(listenerPort uint16) error {
	selfTGID, err := b.probeSelfTGID()
	if err != nil {
		return err
	}
	return b.loadPrograms(listenerPort, selfTGID)
}

func (b *CgroupBackend) probeSelfTGID() (uint32, error) {
	if b == nil {
		return 0, errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return 0, err
	}
	var selfTGID C.uint32_t
	var savedErrno C.int
	if C.singbox_ebpf_cgroup_probe_self_tgid(b.runtime, &selfTGID, &savedErrno) != 0 {
		return 0, eBPFOperationError("probe BPF-visible self TGID", syscall.Errno(savedErrno))
	}
	return uint32(selfTGID), nil
}

func (b *CgroupBackend) loadPrograms(listenerPort uint16, selfTGID uint32) error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return err
	}
	if len(cgroupObject) == 0 {
		return E.New("missing embedded cgroup eBPF object")
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
		(*C.uint8_t)(unsafe.Pointer(&cgroupObject[0])),
		C.size_t(len(cgroupObject)),
		C.uint16_t(listenerPort),
		C.uint32_t(selfTGID),
		C.bool(b.redirectIPv4.IsValid()),
		C.bool(b.hijackDNS),
		C.uint32_t(b.udpTimeoutSeconds),
		redirectIPv4Pointer,
		redirectIPv4Bits,
		C.bool(b.enableIPv6),
		redirectIPv6Pointer,
		redirectIPv6Bits,
		&savedErrno,
	) != 0 {
		return eBPFBackendOperationError(
			"load eBPF inbound programs",
			C.GoString(C.singbox_ebpf_cgroup_error_stage(b.runtime)),
			syscall.Errno(savedErrno),
		)
	}
	b.socketBypassMapFD = int(b.runtime.bypass_socket_cookie_map_fd)
	if b.runtime.self_bypass_tgid {
		b.pendingSocketCookies = nil
		return nil
	}
	value := uint8(1)
	for cookie := range b.pendingSocketCookies {
		cookie := cookie
		if err := updateMap(
			b.socketBypassMapFD,
			unsafe.Pointer(&cookie),
			unsafe.Pointer(&value),
		); err != nil {
			return E.Cause(err, "register pending eBPF bypass socket")
		}
	}
	b.pendingSocketCookies = nil
	return nil
}

func (b *CgroupBackend) UpdateIPv6Available(available bool) (bool, error) {
	if b == nil {
		return false, errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	return b.updateIPv6AvailableLocked(available)
}

func (b *CgroupBackend) updateIPv6AvailableLocked(available bool) (bool, error) {
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return false, err
	}
	if !b.autoIPv6 || b.ipv6AvailableMapFD < 0 {
		return false, nil
	}
	if b.ipv6Available == available {
		return false, nil
	}
	key := uint32(0)
	value := uint32(0)
	if available {
		value = 1
	}
	if err := updateMap(
		b.ipv6AvailableMapFD,
		unsafe.Pointer(&key),
		unsafe.Pointer(&value),
	); err != nil {
		return false, E.Cause(err, "update IPv6 availability eBPF map")
	}
	b.ipv6Available = available
	return true, nil
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
	if err := b.health.requireUsable(b.runtime != nil); err != nil {
		return err
	}
	var savedErrno C.int
	if C.singbox_ebpf_cgroup_attach(b.runtime, &savedErrno) != 0 {
		return eBPFBackendOperationError(
			"attach eBPF inbound",
			C.GoString(C.singbox_ebpf_cgroup_error_stage(b.runtime)),
			syscall.Errno(savedErrno),
		)
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
		b.pendingSocketCookies = nil
		b.bypassIPv4CIDRMapFD = -1
		b.bypassIPv6CIDRMapFD = -1
		b.ipv6AvailableMapFD = -1
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
