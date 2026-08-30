//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	cgroupProgramConnect4 = iota
	cgroupProgramUDP4Sendmsg
	cgroupProgramUDP4Recvmsg
	cgroupProgramConnect6
	cgroupProgramUDP6Sendmsg
	cgroupProgramUDP6Recvmsg
	cgroupProgramSocketRelease
	cgroupProgramCount
)

const (
	cgroupUDPCleanupDisabled      = "disabled"
	cgroupUDPCleanupSocketRelease = "socket_release"
	cgroupUDPCleanupLRUFallback   = "lru_fallback"
	cgroupUDPCleanupInvalid       = "invalid"
)

type cgroupProgramDefinition struct {
	name       string
	attachType CiliumEBPF.AttachType
}

var cgroupProgramDefinitions = [cgroupProgramCount]cgroupProgramDefinition{
	{name: "sb_ebpf_conn4", attachType: CiliumEBPF.AttachCGroupInet4Connect},
	{name: "sb_ebpf_udp4", attachType: CiliumEBPF.AttachCGroupUDP4Sendmsg},
	{name: "sb_ebpf_urcv4", attachType: CiliumEBPF.AttachCGroupUDP4Recvmsg},
	{name: "sb_ebpf_conn6", attachType: CiliumEBPF.AttachCGroupInet6Connect},
	{name: "sb_ebpf_udp6", attachType: CiliumEBPF.AttachCGroupUDP6Sendmsg},
	{name: "sb_ebpf_urcv6", attachType: CiliumEBPF.AttachCGroupUDP6Recvmsg},
	{name: "sb_ebpf_rel", attachType: CiliumEBPF.AttachCgroupInetSockRelease},
}

type cgroupRuntime struct {
	cgroupFile                  *os.File
	maps                        map[string]*CiliumEBPF.Map
	programs                    []*CiliumEBPF.Program
	links                       [cgroupProgramCount]link.Link
	attached                    [cgroupProgramCount]bool
	control_map_fd              int
	tcp_redirect_map_fd         int
	udp_redirect_map_fd         int
	udp_recovery_map_fd         int
	udp_token_map_fd            int
	udp_peer_map_fd             int
	udp_flow_map_fd             int
	bypass_socket_cookie_map_fd int
	uid_policy_map_fd           int
	bypass_ipv4_cidr_map_fd     int
	bypass_ipv6_cidr_map_fd     int
	host_ipv4_map_fd            int
	host_ipv6_map_fd            int
	socket_release_supported    bool
	coarse_time_supported       bool
	socket_storage_supported    bool
	enable_tcp                  bool
	enable_udp                  bool
	uid_policy                  bool
	uid_default_bypass          bool
	bypass_ipv4_policy          bool
	bypass_ipv6_policy          bool
	bypass_port_policy          bool
}

type CgroupBackend struct {
	access                         sync.RWMutex
	health                         backendHealth
	udpRecoveryAccess              sync.Mutex
	udpReplyTokenSequence          atomic.Uint64
	connectedUDPTokenLookupSupport mapBatchSupport
	connectedUDPTokenKeys          []uint64
	connectedUDPTokenValues        []listenerLookupKey
	lookupAndDeleteMode            atomic.Int32
	udpRecoveryConsumeMode         atomic.Int32
	runtime                        *cgroupRuntime
	mapCapacity                    CgroupMapCapacity
	tcpRedirectMapFD               int
	udpRedirectMapFD               int
	udpRecoveryMapFD               int
	udpFlowMapFD                   int
	socketBypassMapFD              int
	bypassIPv4CIDRMapFD            int
	bypassIPv6CIDRMapFD            int
	hostIPv4MapFD                  int
	hostIPv6MapFD                  int
	bypassIPv4CIDR                 []netip.Prefix
	bypassIPv6CIDR                 []netip.Prefix
	hostIPv4                       []netip.Prefix
	hostIPv6                       []netip.Prefix
	cgroupPath                     string
	redirectIPv4                   netip.Prefix
	redirectIPv6                   netip.Prefix
	fakeIPIPv4                     netip.Prefix
	fakeIPIPv6                     netip.Prefix
	enableIPv6                     bool
	enableUDP                      bool
	dnsMode                        DNSMode
	bypassPrivateAddress           bool
	udpTimeoutSeconds              uint32
	listenerPort                   uint16
}

func PrepareCgroup(config CgroupConfig) (*CgroupBackend, error) {
	cgroupPath := config.Path
	redirectIPv4 := config.RedirectIPv4
	redirectIPv6 := config.RedirectIPv6
	mapCapacity := config.MapCapacity
	policy := config.Policy
	var err error
	fakeIPIPv4 := policy.fakeIPIPv4
	fakeIPIPv6 := policy.fakeIPIPv6
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
	if !redirectIPv4.IsValid() && !config.EnableIPv6 {
		return nil, E.New("eBPF cgroup backend has no enabled address family")
	}
	udpTimeoutSeconds := uint32(0)
	if config.EnableUDP {
		udpTimeoutSeconds, err = cgroupUDPTimeoutSeconds(config.UDPTimeout)
		if err != nil {
			return nil, err
		}
	}
	uidPolicyEntries, uidDefaultBypass := policy.uidEntries, policy.uidDefaultBypass
	if err = checkLPMTriePolicyCompatibility("UID", len(uidPolicyEntries)); err != nil {
		return nil, err
	}
	if cgroupPath == "" {
		cgroupPath, err = DetectCgroup2Root()
		if err != nil {
			return nil, err
		}
	}
	memlockErr := raiseMemlockLimit()
	if err = checkKernelCapabilities("cgroup", cgroupPath); err != nil {
		if memlockErr != nil {
			return nil, E.Errors(err, E.Cause(memlockErr, "remove memlock limit"))
		}
		return nil, err
	}
	cgroupFile, err := os.Open(cgroupPath)
	if err != nil {
		return nil, eBPFOperationError("open cgroup", err)
	}
	if err = unix.Flock(int(cgroupFile.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		_ = cgroupFile.Close()
		if errors.Is(err, unix.EWOULDBLOCK) {
			err = unix.EBUSY
		}
		return nil, eBPFOperationError("lock cgroup", err)
	}
	if err = detachOwnedCgroupPrograms(int(cgroupFile.Fd())); err != nil {
		_ = cgroupFile.Close()
		return nil, eBPFOperationError("detach stale cgroup programs", err)
	}
	socketReleaseSupported := false
	coarseTimeSupported := false
	socketStorageSupported := false
	if config.EnableUDP {
		coarseTimeSupported = features.HaveProgramHelper(CiliumEBPF.CGroupSockAddr, asm.FnKtimeGetCoarseNs) == nil
		socketStorageSupported = probeCgroupSocketStorageSupport()
		socketReleaseSupported, err = probeSocketReleaseSupport(int(cgroupFile.Fd()))
		if err != nil {
			_ = cgroupFile.Close()
			return nil, eBPFOperationError("probe socket release attachment", err)
		}
	}
	runtimeState := &cgroupRuntime{
		cgroupFile:               cgroupFile,
		maps:                     make(map[string]*CiliumEBPF.Map),
		programs:                 make([]*CiliumEBPF.Program, cgroupProgramCount),
		enable_tcp:               config.EnableTCP,
		enable_udp:               config.EnableUDP,
		uid_policy:               len(uidPolicyEntries) > 0 || uidDefaultBypass,
		uid_default_bypass:       uidDefaultBypass,
		bypass_ipv4_policy:       policy.local.EnableBypassCIDR && redirectIPv4.IsValid(),
		bypass_ipv6_policy:       policy.local.EnableBypassCIDR && redirectIPv6.IsValid(),
		bypass_port_policy:       len(policy.localBypassPortEntries) > 0,
		socket_release_supported: socketReleaseSupported,
		coarse_time_supported:    coarseTimeSupported,
		socket_storage_supported: socketStorageSupported,
	}
	if err = prepareCgroupMaps(runtimeState, mapCapacity, len(uidPolicyEntries), config.SelfBypassMap); err != nil {
		_ = closeMaps(runtimeState.maps)
		_ = runtimeState.cgroupFile.Close()
		if memlockErr != nil && (errors.Is(err, unix.ENOMEM) || errors.Is(err, unix.EPERM)) {
			err = E.Errors(err, E.Cause(memlockErr, "remove memlock limit"))
		}
		return nil, err
	}
	backend := &CgroupBackend{
		mapCapacity:          mapCapacity,
		runtime:              runtimeState,
		tcpRedirectMapFD:     runtimeState.tcp_redirect_map_fd,
		udpRedirectMapFD:     runtimeState.udp_redirect_map_fd,
		udpRecoveryMapFD:     runtimeState.udp_recovery_map_fd,
		udpFlowMapFD:         runtimeState.udp_flow_map_fd,
		socketBypassMapFD:    runtimeState.bypass_socket_cookie_map_fd,
		bypassIPv4CIDRMapFD:  runtimeState.bypass_ipv4_cidr_map_fd,
		bypassIPv6CIDRMapFD:  runtimeState.bypass_ipv6_cidr_map_fd,
		hostIPv4MapFD:        runtimeState.host_ipv4_map_fd,
		hostIPv6MapFD:        runtimeState.host_ipv6_map_fd,
		cgroupPath:           cgroupPath,
		redirectIPv4:         redirectIPv4,
		redirectIPv6:         redirectIPv6,
		fakeIPIPv4:           fakeIPIPv4,
		fakeIPIPv6:           fakeIPIPv6,
		enableIPv6:           config.EnableIPv6,
		enableUDP:            config.EnableUDP,
		dnsMode:              policy.local.DNSMode,
		bypassPrivateAddress: policy.local.BypassPrivateAddress,
		udpTimeoutSeconds:    udpTimeoutSeconds,
	}
	if err = populateCompiledPolicyMaps(policyMapTargets{
		Scope:     "cgroup eBPF",
		UID:       runtimeState.maps["cgroup_uid_policy"],
		LocalPort: runtimeState.maps["cgroup_bypass_port"],
	}, policy); err != nil {
		_ = backend.Close()
		return nil, err
	}
	return backend, nil
}
