//go:build with_ebpf && (linux || android) && cgo

package ebpf

/*
#cgo CFLAGS: -I${SRCDIR}/native
#include <errno.h>
#include <stdlib.h>
#include "singbox_ebpf.h"

static int singbox_ebpf_inbound_prepare(
	const char *cgroup_path,
	uint16_t listen_port,
	bool enable_tcp,
	bool enable_udp,
	bool enable_ipv4,
	bool enable_bypass_cidr,
	bool hijack_dns,
	const uint8_t *redirect_ipv4,
	uint32_t redirect_ipv4_prefix_bits,
	bool enable_ipv6,
	const uint8_t *redirect_ipv6,
	uint32_t redirect_ipv6_prefix_bits,
	uint32_t include_uid_entries,
	uint32_t exclude_uid_entries,
	struct sb_ebpf_inbound_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_inbound_prepare(
		cgroup_path,
		listen_port,
		enable_tcp,
		enable_udp,
		enable_ipv4,
		enable_bypass_cidr,
		hijack_dns,
		redirect_ipv4,
		redirect_ipv4_prefix_bits,
		enable_ipv6,
		redirect_ipv6,
		redirect_ipv6_prefix_bits,
		include_uid_entries,
		exclude_uid_entries,
		runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_inbound_attach(
	struct sb_ebpf_inbound_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_inbound_attach(runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_inbound_close(
	struct sb_ebpf_inbound_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_inbound_close(runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}
*/
import "C"

import (
	"errors"
	"net/netip"
	"runtime"
	"slices"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	bpfMapCreate     = 0
	bpfMapLookupElem = 1
	bpfMapUpdateElem = 2
	bpfMapDeleteElem = 3
	bpfMapTypeArray  = 2
	bpfNoExist       = 1
)

type Backend struct {
	access             sync.RWMutex
	runtime            *C.struct_sb_ebpf_inbound_runtime
	tcpRedirectMap     int
	udpRedirectMap     int
	udpTokenMap        int
	statsMap           int
	cookieMap          int
	bypassIPv4CIDRMap  int
	bypassIPv6CIDRMap  int
	bypassIPv4CIDR     []netip.Prefix
	bypassIPv6CIDR     []netip.Prefix
	cgroupPath         string
	enableUDP          bool
	hijackDNS          bool
	lookupMisses       atomic.Uint64
	tcpRedirectDeletes atomic.Uint64
	udpRedirectDeletes atomic.Uint64
}

type mapElementAttr struct {
	MapFD uint32
	_     uint32
	Key   uint64
	Value uint64
	Flags uint64
}

type mapCreateAttr struct {
	MapType    uint32
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	MapFlags   uint32
}

func Prepare(
	cgroupPath string,
	listenPort uint16,
	enableTCP bool,
	enableUDP bool,
	redirectIPv4 netip.Prefix,
	redirectIPv6 netip.Prefix,
	policy Policy,
) (*Backend, error) {
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
	runtimeState := (*C.struct_sb_ebpf_inbound_runtime)(C.calloc(1, C.size_t(C.sizeof_struct_sb_ebpf_inbound_runtime)))
	if runtimeState == nil {
		return nil, E.New("allocate eBPF runtime")
	}
	var cgroupPathCString *C.char
	if cgroupPath != "" {
		cgroupPathCString = C.CString(cgroupPath)
		defer C.free(unsafe.Pointer(cgroupPathCString))
	}
	var savedErrno C.int
	var redirectIPv4Bytes [4]byte
	var redirectIPv4Pointer *C.uint8_t
	var redirectIPv4Bits C.uint32_t
	if redirectIPv4.IsValid() {
		redirectIPv4Bytes = redirectIPv4.Addr().As4()
		redirectIPv4Pointer = (*C.uint8_t)(unsafe.Pointer(&redirectIPv4Bytes[0]))
		redirectIPv4Bits = C.uint32_t(redirectIPv4.Bits())
	}
	var redirectIPv6Bytes [16]byte
	var redirectIPv6Pointer *C.uint8_t
	var redirectIPv6Bits C.uint32_t
	if redirectIPv6.IsValid() {
		redirectIPv6Bytes = redirectIPv6.Addr().As16()
		redirectIPv6Pointer = (*C.uint8_t)(unsafe.Pointer(&redirectIPv6Bytes[0]))
		redirectIPv6Bits = C.uint32_t(redirectIPv6.Bits())
	}
	if C.singbox_ebpf_inbound_prepare(
		cgroupPathCString,
		C.uint16_t(listenPort),
		C.bool(enableTCP),
		C.bool(enableUDP),
		C.bool(redirectIPv4.IsValid()),
		C.bool(policy.EnableBypassCIDR),
		C.bool(policy.HijackDNS),
		redirectIPv4Pointer,
		redirectIPv4Bits,
		C.bool(redirectIPv6.IsValid()),
		redirectIPv6Pointer,
		redirectIPv6Bits,
		C.uint32_t(len(includeUIDEntries)),
		C.uint32_t(len(excludeUIDEntries)),
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
	backend := &Backend{
		runtime:           runtimeState,
		tcpRedirectMap:    int(runtimeState.tcp_redirect_map_fd),
		udpRedirectMap:    int(runtimeState.udp_redirect_map_fd),
		udpTokenMap:       int(runtimeState.udp_token_map_fd),
		statsMap:          int(runtimeState.stats_map_fd),
		cookieMap:         int(runtimeState.bypass_socket_cookie_map_fd),
		bypassIPv4CIDRMap: int(runtimeState.bypass_ipv4_cidr_map_fd),
		bypassIPv6CIDRMap: int(runtimeState.bypass_ipv6_cidr_map_fd),
		cgroupPath:        cgroupPath,
		enableUDP:         enableUDP,
		hijackDNS:         policy.HijackDNS,
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

func compileUIDPolicy(name string, uidRanges []UIDRange) ([]uidLPMKey, error) {
	for _, uidRange := range uidRanges {
		if uidRange.Start > uidRange.End {
			return nil, E.New("invalid ", name, " range: ", uidRange.Start, ":", uidRange.End)
		}
	}
	entries := compileUIDRanges(uidRanges)
	if len(entries) > maxUIDPolicyEntries {
		return nil, E.New(name, " compiles to too many eBPF map entries: ", len(entries), " > ", maxUIDPolicyEntries)
	}
	return entries, nil
}

func populateUIDPolicyMap(mapFD int, entries []uidLPMKey) error {
	if len(entries) == 0 {
		return nil
	}
	value := uint8(1)
	for entryIndex := range entries {
		if err := updateMap(mapFD, unsafe.Pointer(&entries[entryIndex]), unsafe.Pointer(&value)); err != nil {
			return err
		}
	}
	return nil
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

func (b *Backend) CgroupPath() string {
	if b == nil {
		return ""
	}
	return b.cgroupPath
}

func (b *Backend) AttachedPrograms() []string {
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

func (b *Backend) Attach() error {
	if b == nil {
		return osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return osErrClosed
	}
	var savedErrno C.int
	if C.singbox_ebpf_inbound_attach(b.runtime, &savedErrno) != 0 {
		return eBPFOperationError("attach eBPF inbound", syscall.Errno(savedErrno))
	}
	return nil
}

func (b *Backend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	var savedErrno C.int
	result := C.singbox_ebpf_inbound_close(b.runtime, &savedErrno)
	if b.runtime.cgroup_fd < 0 && b.runtime.attached_programs == 0 {
		C.free(unsafe.Pointer(b.runtime))
		b.runtime = nil
		b.tcpRedirectMap = -1
		b.udpRedirectMap = -1
		b.udpTokenMap = -1
		b.statsMap = -1
		b.cookieMap = -1
		b.bypassIPv4CIDRMap = -1
		b.bypassIPv6CIDRMap = -1
		b.bypassIPv4CIDR = nil
		b.bypassIPv6CIDR = nil
	}
	if result != 0 {
		return E.Cause(syscall.Errno(savedErrno), "close eBPF inbound")
	}
	return nil
}

func (b *Backend) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime == nil
}

func (b *Backend) UpdateBypassCIDR(prefixes []netip.Prefix) (bool, error) {
	ipv4Prefixes, ipv6Prefixes, err := compileBypassCIDRPolicy(prefixes)
	if err != nil {
		return false, E.Cause(err, "compile bypass CIDR policy")
	}
	if len(ipv4Prefixes) > maxBypassCIDRPolicyEntries {
		return false, E.New("IPv4 bypass CIDR policy has too many eBPF map entries: ",
			len(ipv4Prefixes), " > ", maxBypassCIDRPolicyEntries)
	}
	if len(ipv6Prefixes) > maxBypassCIDRPolicyEntries {
		return false, E.New("IPv6 bypass CIDR policy has too many eBPF map entries: ",
			len(ipv6Prefixes), " > ", maxBypassCIDRPolicyEntries)
	}
	if b == nil {
		return false, osErrClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return false, osErrClosed
	}
	ipv4Changed := !slices.Equal(b.bypassIPv4CIDR, ipv4Prefixes)
	ipv6Changed := !slices.Equal(b.bypassIPv6CIDR, ipv6Prefixes)
	if !ipv4Changed && !ipv6Changed {
		return false, nil
	}
	if ipv6Changed {
		if err = replaceBypassCIDRPolicyMap(
			b.bypassIPv6CIDRMap,
			b.bypassIPv6CIDR,
			ipv6Prefixes,
		); err != nil {
			return false, E.Cause(err, "update IPv6 bypass CIDR eBPF map")
		}
	}
	if ipv4Changed {
		if err = replaceBypassCIDRPolicyMap(
			b.bypassIPv4CIDRMap,
			b.bypassIPv4CIDR,
			ipv4Prefixes,
		); err != nil {
			var rollbackErr error
			if ipv6Changed {
				rollbackErr = replaceBypassCIDRPolicyMap(
					b.bypassIPv6CIDRMap,
					ipv6Prefixes,
					b.bypassIPv6CIDR,
				)
			}
			updateErr := E.Cause(err, "update IPv4 bypass CIDR eBPF map")
			if rollbackErr != nil {
				updateErr = E.Errors(
					updateErr,
					E.Cause(rollbackErr, "rollback IPv6 bypass CIDR eBPF map"),
				)
			}
			return false, updateErr
		}
	}
	b.bypassIPv4CIDR = slices.Clone(ipv4Prefixes)
	b.bypassIPv6CIDR = slices.Clone(ipv6Prefixes)
	return true, nil
}

func (b *Backend) BypassCIDRCount() (int, int) {
	if b == nil {
		return 0, 0
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return len(b.bypassIPv4CIDR), len(b.bypassIPv6CIDR)
}

func replaceBypassCIDRPolicyMap(
	mapFD int,
	currentPrefixes []netip.Prefix,
	nextPrefixes []netip.Prefix,
) error {
	additions, removals := bypassCIDRPolicyDelta(currentPrefixes, nextPrefixes)
	if len(additions) == 0 && len(removals) == 0 {
		return nil
	}
	if mapFD < 0 {
		return osErrClosed
	}
	value := uint8(1)
	added := make([]netip.Prefix, 0, len(additions))
	for _, prefix := range additions {
		err := updateBypassCIDRMapEntry(mapFD, prefix, &value, bpfNoExist)
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return E.Errors(err, rollbackBypassCIDRPolicyMap(mapFD, added, nil))
		}
		added = append(added, prefix)
	}
	removed := make([]netip.Prefix, 0, len(removals))
	for _, prefix := range removals {
		err := deleteBypassCIDRMapEntry(mapFD, prefix)
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return E.Errors(err, rollbackBypassCIDRPolicyMap(mapFD, added, removed))
		}
		removed = append(removed, prefix)
	}
	return nil
}

func rollbackBypassCIDRPolicyMap(mapFD int, added []netip.Prefix, removed []netip.Prefix) error {
	var rollbackErr error
	value := uint8(1)
	for _, prefix := range removed {
		if err := updateBypassCIDRMapEntry(mapFD, prefix, &value, 0); err != nil {
			rollbackErr = E.Errors(rollbackErr, err)
		}
	}
	for _, prefix := range added {
		if err := deleteBypassCIDRMapEntry(mapFD, prefix); err != nil && !errors.Is(err, unix.ENOENT) {
			rollbackErr = E.Errors(rollbackErr, err)
		}
	}
	return rollbackErr
}

func updateBypassCIDRMapEntry(mapFD int, prefix netip.Prefix, value *uint8, flags uint64) error {
	if prefix.Addr().Is4() {
		key := ipv4CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As4()}
		return updateMapWithFlags(mapFD, unsafe.Pointer(&key), unsafe.Pointer(value), flags)
	}
	key := ipv6CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
	return updateMapWithFlags(mapFD, unsafe.Pointer(&key), unsafe.Pointer(value), flags)
}

func deleteBypassCIDRMapEntry(mapFD int, prefix netip.Prefix) error {
	if prefix.Addr().Is4() {
		key := ipv4CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As4()}
		return deleteMap(mapFD, unsafe.Pointer(&key))
	}
	key := ipv6CIDRLPMKey{PrefixLength: uint32(prefix.Bits()), Address: prefix.Addr().As16()}
	return deleteMap(mapFD, unsafe.Pointer(&key))
}

func (b *Backend) ProtectFunc() control.Func {
	if b == nil {
		return nil
	}
	return func(network string, address string, rawConn syscall.RawConn) error {
		return control.Raw(rawConn, func(fd uintptr) error {
			b.access.RLock()
			defer b.access.RUnlock()
			if b.runtime == nil {
				return osErrClosed
			}
			cookie, err := socketCookie(fd)
			if err != nil {
				return E.Cause(err, "read socket cookie")
			}
			value := uint8(1)
			if err = updateMap(b.cookieMap, unsafe.Pointer(&cookie), unsafe.Pointer(&value)); err != nil {
				return E.Cause(err, "register eBPF bypass socket")
			}
			return nil
		})
	}
}

func (b *Backend) LookupOriginal(protocol uint8, redirect netip.AddrPort) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, redirect, false)
}

func (b *Backend) TakeOriginal(protocol uint8, redirect netip.AddrPort) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, redirect, true)
}

func (b *Backend) lookupOriginal(
	protocol uint8,
	redirect netip.AddrPort,
	deleteAfterLookup bool,
) (OriginalDestination, error) {
	if b == nil {
		return OriginalDestination{}, osErrClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, osErrClosed
	}
	key, err := makeRedirectKey(protocol, redirect)
	if err != nil {
		return OriginalDestination{}, err
	}
	var original originalDestination
	redirectMap, err := b.redirectMap(protocol)
	if err != nil {
		return OriginalDestination{}, err
	}
	err = lookupMap(redirectMap, unsafe.Pointer(&key), unsafe.Pointer(&original))
	if err != nil {
		b.lookupMisses.Add(1)
		return OriginalDestination{}, E.Cause(err, "lookup original destination")
	}
	var address netip.Addr
	switch original.Family {
	case addressFamilyIPv4:
		address = netip.AddrFrom4([4]byte(original.Addr[:4]))
	case addressFamilyIPv6:
		address = netip.AddrFrom16(original.Addr)
	default:
		return OriginalDestination{}, E.New("invalid original destination family: ", original.Family)
	}
	if deleteAfterLookup {
		err = deleteMap(redirectMap, unsafe.Pointer(&key))
		if err != nil && !errors.Is(err, unix.ENOENT) {
			return OriginalDestination{}, E.Cause(err, "delete consumed redirect mapping")
		}
		if err == nil {
			b.addRedirectDelete(protocol)
		}
	}
	return OriginalDestination{
		Destination:  netip.AddrPortFrom(address.Unmap(), original.Port),
		ConnectedUDP: original.Flags&1 != 0,
		UID:          original.UID,
	}, nil
}

func (b *Backend) DeleteRedirect(protocol uint8, redirect netip.AddrPort) error {
	if b == nil {
		return osErrClosed
	}
	key, err := makeRedirectKey(protocol, redirect)
	if err != nil {
		return err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return osErrClosed
	}
	redirectMap, err := b.redirectMap(protocol)
	if err != nil {
		return err
	}
	err = deleteMap(redirectMap, unsafe.Pointer(&key))
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "delete redirect mapping")
	}
	b.addRedirectDelete(protocol)
	return nil
}

func (b *Backend) redirectMap(protocol uint8) (int, error) {
	switch protocol {
	case ProtocolTCP:
		return b.tcpRedirectMap, nil
	case ProtocolUDP:
		return b.udpRedirectMap, nil
	default:
		return -1, E.New("unsupported eBPF redirect protocol: ", protocol)
	}
}

func (b *Backend) addRedirectDelete(protocol uint8) {
	if protocol == ProtocolTCP {
		b.tcpRedirectDeletes.Add(1)
	} else {
		b.udpRedirectDeletes.Add(1)
	}
}

func lookupMap(mapFD int, key unsafe.Pointer, value unsafe.Pointer) error {
	return mapOperation(bpfMapLookupElem, mapFD, key, value, 0)
}

func updateMap(mapFD int, key unsafe.Pointer, value unsafe.Pointer) error {
	return updateMapWithFlags(mapFD, key, value, 0)
}

func updateMapWithFlags(mapFD int, key unsafe.Pointer, value unsafe.Pointer, flags uint64) error {
	return mapOperation(bpfMapUpdateElem, mapFD, key, value, flags)
}

func deleteMap(mapFD int, key unsafe.Pointer) error {
	return mapOperation(bpfMapDeleteElem, mapFD, key, nil, 0)
}

func mapOperation(command uintptr, mapFD int, key unsafe.Pointer, value unsafe.Pointer, flags uint64) error {
	if mapFD < 0 {
		return osErrClosed
	}
	attribute := mapElementAttr{
		MapFD: uint32(mapFD),
		Key:   uint64(uintptr(key)),
		Value: uint64(uintptr(value)),
		Flags: flags,
	}
	_, _, errno := unix.Syscall(unix.SYS_BPF, command, uintptr(unsafe.Pointer(&attribute)), unsafe.Sizeof(attribute))
	runtime.KeepAlive(key)
	runtime.KeepAlive(value)
	if errno != 0 {
		return errno
	}
	return nil
}

func socketCookie(fd uintptr) (uint64, error) {
	var cookie uint64
	length := uint32(unsafe.Sizeof(cookie))
	_, _, errno := unix.Syscall6(
		unix.SYS_GETSOCKOPT,
		fd,
		unix.SOL_SOCKET,
		unix.SO_COOKIE,
		uintptr(unsafe.Pointer(&cookie)),
		uintptr(unsafe.Pointer(&length)),
		0,
	)
	if errno != 0 {
		return 0, errno
	}
	return cookie, nil
}

var osErrClosed = syscall.EBADF
