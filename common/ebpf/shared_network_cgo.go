//go:build with_ebpf && (linux || android) && cgo

package ebpf

/*
#cgo CFLAGS: -I${SRCDIR}/native
#include <errno.h>
#include <stdlib.h>
#include "runtime.h"

static int singbox_ebpf_shared_network_prepare(
	const uint8_t *object,
	size_t object_size,
	int bypass_ipv4_map_fd,
	int bypass_ipv6_map_fd,
	uint32_t proxy_capacity,
	uint32_t bypass_capacity,
	uint32_t fragment_capacity,
	struct sb_ebpf_shared_network_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_shared_network_prepare(
		object,
		object_size,
		bypass_ipv4_map_fd,
		bypass_ipv6_map_fd,
		proxy_capacity,
		bypass_capacity,
		fragment_capacity,
		runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static int singbox_ebpf_shared_network_close(
	struct sb_ebpf_shared_network_runtime *runtime,
	int *saved_errno) {
	int result = sb_ebpf_shared_network_close(runtime);
	if (result != 0) *saved_errno = errno;
	return result;
}

static const char *singbox_ebpf_shared_network_error_stage(
	const struct sb_ebpf_shared_network_runtime *runtime) {
	return runtime == NULL ? NULL : runtime->error_stage;
}
*/
import "C"

import (
	_ "embed"
	"net/netip"
	"sync"
	"syscall"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"
)

//go:embed native/shared_network.bpf.o
var sharedNetworkObject []byte

type SharedNetworkBackend struct {
	access            sync.RWMutex
	health            backendHealth
	flowAccess        sync.Mutex
	flowReferences    map[SharedNetworkFlowHandle]uint32
	runtime           *C.struct_sb_ebpf_shared_network_runtime
	control           sharedNetworkControl
	hostIPv4          []netip.Prefix
	hostIPv6          []netip.Prefix
	bypassIPv4MapFD   int
	bypassIPv6MapFD   int
	bypassIPv4CIDR    []netip.Prefix
	bypassIPv6CIDR    []netip.Prefix
	includeSourceIPv4 []netip.Prefix
	includeSourceIPv6 []netip.Prefix
	excludeSourceIPv4 []netip.Prefix
	excludeSourceIPv6 []netip.Prefix
	includeSourceMAC  []MACAddress
	excludeSourceMAC  []MACAddress
}

func PrepareSharedNetwork(cgroupBackend *CgroupBackend, config SharedNetworkConfig) (*SharedNetworkBackend, error) {
	redirectIPv4 := config.RedirectIPv4
	redirectIPv6 := config.RedirectIPv6
	for name, capacity := range map[string]uint32{
		"shared-network proxy":    config.MapCapacity.Proxy,
		"shared-network bypass":   config.MapCapacity.Bypass,
		"shared-network fragment": config.MapCapacity.Fragment,
	} {
		if err := validateMapCapacity(name, capacity); err != nil {
			return nil, err
		}
	}
	if config.ListenerPort == 0 {
		return nil, E.New("missing shared-network listener port")
	}
	udpTimeoutSeconds, err := sharedNetworkUDPTimeoutSeconds(config.UDPTimeout)
	if err != nil {
		return nil, err
	}
	if redirectIPv4.IsValid() {
		redirectIPv4 = redirectIPv4.Masked()
		if err := ValidateRedirectPrefix(redirectIPv4); err != nil {
			return nil, err
		}
	}
	if redirectIPv6.IsValid() {
		redirectIPv6 = redirectIPv6.Masked()
		if err := ValidateRedirectPrefix(redirectIPv6); err != nil {
			return nil, err
		}
	}
	if !redirectIPv4.IsValid() && !redirectIPv6.IsValid() {
		return nil, E.New("missing shared-network redirect address")
	}
	if len(sharedNetworkObject) == 0 {
		return nil, E.New("missing embedded shared-network eBPF object")
	}
	memlockErr := raiseMemlockLimit()
	if err := checkKernelCapabilities("shared-network", ""); err != nil {
		if memlockErr != nil {
			return nil, E.Errors(err, E.Cause(memlockErr, "remove memlock limit"))
		}
		return nil, err
	}

	runtimeState := (*C.struct_sb_ebpf_shared_network_runtime)(C.calloc(
		1,
		C.size_t(C.sizeof_struct_sb_ebpf_shared_network_runtime),
	))
	if runtimeState == nil {
		return nil, E.New("allocate shared-network token runtime")
	}
	bypassIPv4MapFD := -1
	bypassIPv6MapFD := -1
	if cgroupBackend != nil {
		cgroupBackend.access.RLock()
		if err := cgroupBackend.health.requireUsable(cgroupBackend.runtime != nil); err != nil {
			cgroupBackend.access.RUnlock()
			C.free(unsafe.Pointer(runtimeState))
			return nil, err
		}
		bypassIPv4MapFD = cgroupBackend.bypassIPv4CIDRMapFD
		bypassIPv6MapFD = cgroupBackend.bypassIPv6CIDRMapFD
	}
	var savedErrno C.int
	result := C.singbox_ebpf_shared_network_prepare(
		(*C.uint8_t)(unsafe.Pointer(&sharedNetworkObject[0])),
		C.size_t(len(sharedNetworkObject)),
		C.int(bypassIPv4MapFD),
		C.int(bypassIPv6MapFD),
		C.uint32_t(config.MapCapacity.Proxy),
		C.uint32_t(config.MapCapacity.Bypass),
		C.uint32_t(config.MapCapacity.Fragment),
		runtimeState,
		&savedErrno,
	)
	if cgroupBackend != nil {
		cgroupBackend.access.RUnlock()
	}
	if result != 0 {
		errorStage := C.GoString(C.singbox_ebpf_shared_network_error_stage(runtimeState))
		C.free(unsafe.Pointer(runtimeState))
		prepareErr := eBPFBackendOperationError(
			"prepare shared-network programs",
			errorStage,
			syscall.Errno(savedErrno),
		)
		if memlockErr != nil && (savedErrno == C.int(syscall.ENOMEM) || savedErrno == C.int(syscall.EPERM)) {
			prepareErr = E.Errors(prepareErr, E.Cause(memlockErr, "remove memlock limit"))
		}
		return nil, prepareErr
	}

	if bypassIPv4MapFD < 0 {
		bypassIPv4MapFD = int(runtimeState.fallback_bypass_ipv4_map_fd)
	}
	if bypassIPv6MapFD < 0 {
		bypassIPv6MapFD = int(runtimeState.fallback_bypass_ipv6_map_fd)
	}
	backend := &SharedNetworkBackend{
		runtime:         runtimeState,
		bypassIPv4MapFD: bypassIPv4MapFD,
		bypassIPv6MapFD: bypassIPv6MapFD,
	}
	backend.control.ListenerPort = config.ListenerPort
	backend.control.UDPTimeoutSeconds = udpTimeoutSeconds
	if config.EnableTCP {
		backend.control.Flags |= sharedNetworkFlagTCP
	}
	if config.EnableUDP {
		backend.control.Flags |= sharedNetworkFlagUDP
	}
	if config.HijackDNS {
		backend.control.Flags |= sharedNetworkFlagDNSHijack
	}
	if config.BypassPrivateAddress {
		backend.control.Flags |= sharedNetworkFlagBypassPrivateAddress
	}
	if redirectIPv4.IsValid() {
		backend.control.Flags |= sharedNetworkFlagIPv4
		backend.control.TokenIPv4Prefix = redirectIPv4.Addr().As4()
		backend.control.TokenIPv4PrefixBits = uint8(redirectIPv4.Bits())
	}
	if redirectIPv6.IsValid() {
		backend.control.Flags |= sharedNetworkFlagIPv6
		backend.control.TokenIPv6Prefix = redirectIPv6.Addr().As16()
		backend.control.TokenIPv6PrefixBits = uint8(redirectIPv6.Bits())
	}
	if err = backend.initializeSourceCIDRPolicy(config.IncludeSourceCIDR, config.ExcludeSourceCIDR); err != nil {
		_ = backend.Close()
		return nil, err
	}
	if err = backend.initializeSourceMACPolicy(config.IncludeSourceMAC, config.ExcludeSourceMAC); err != nil {
		_ = backend.Close()
		return nil, err
	}
	if err := backend.updateControl(); err != nil {
		_ = backend.Close()
		return nil, E.Cause(err, "initialize shared-network control")
	}
	return backend, nil
}

func (b *SharedNetworkBackend) updateControl() error {
	if b == nil || b.runtime == nil {
		return errBackendClosed
	}
	key := uint32(0)
	return updateMap(
		int(b.runtime.control_map_fd),
		unsafe.Pointer(&key),
		unsafe.Pointer(&b.control),
	)
}

func (b *SharedNetworkBackend) Enable() error {
	if b == nil {
		return errBackendClosed
	}
	b.access.Lock()
	defer b.access.Unlock()
	if err := b.requireUsableLocked(); err != nil {
		return err
	}
	previous := b.control.Enabled
	b.control.Enabled = 1
	if err := b.updateControl(); err != nil {
		b.control.Enabled = previous
		return err
	}
	return nil
}

func (b *SharedNetworkBackend) requireUsableLocked() error {
	return b.health.requireUsable(b.runtime != nil)
}

func (b *SharedNetworkBackend) invalidateLocked(operation string, cause error) error {
	rebuildRequired := b.health.invalidate("shared-network", operation)
	b.control.Enabled = 0
	disableErr := b.updateControl()
	if disableErr != nil {
		disableErr = E.Cause(disableErr, "disable unusable shared-network backend")
	}
	return E.Errors(
		cause,
		disableErr,
		rebuildRequired,
	)
}

func (b *SharedNetworkBackend) Disable() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	previous := b.control.Enabled
	b.control.Enabled = 0
	if err := b.updateControl(); err != nil {
		b.control.Enabled = previous
		return err
	}
	return nil
}

func (b *SharedNetworkBackend) IngressProgramFD() int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return -1
	}
	return int(b.runtime.ingress_prog_fd)
}

func (b *SharedNetworkBackend) EgressProgramFD() int {
	if b == nil {
		return -1
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return -1
	}
	return int(b.runtime.egress_prog_fd)
}

func (b *SharedNetworkBackend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	b.control.Enabled = 0
	_ = b.updateControl()
	var savedErrno C.int
	result := C.singbox_ebpf_shared_network_close(b.runtime, &savedErrno)
	if b.runtime.control_map_fd < 0 &&
		b.runtime.ingress_prog_fd < 0 &&
		b.runtime.egress_prog_fd < 0 {
		C.free(unsafe.Pointer(b.runtime))
		b.runtime = nil
		b.hostIPv4 = nil
		b.hostIPv6 = nil
		b.bypassIPv4MapFD = -1
		b.bypassIPv6MapFD = -1
		b.bypassIPv4CIDR = nil
		b.bypassIPv6CIDR = nil
		b.includeSourceIPv4 = nil
		b.includeSourceIPv6 = nil
		b.excludeSourceIPv4 = nil
		b.excludeSourceIPv6 = nil
		b.includeSourceMAC = nil
		b.excludeSourceMAC = nil
		clear(b.flowReferences)
	}
	if result != 0 {
		return E.Cause(syscall.Errno(savedErrno), "close shared-network runtime")
	}
	return nil
}

func (b *SharedNetworkBackend) IsClosed() bool {
	if b == nil {
		return true
	}
	b.access.RLock()
	defer b.access.RUnlock()
	return b.runtime == nil
}
