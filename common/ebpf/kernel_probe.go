//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

type KernelProbeMode string

const (
	KernelProbeModeAll           KernelProbeMode = "all"
	KernelProbeModeLocal         KernelProbeMode = "local"
	KernelProbeModeSharedNetwork KernelProbeMode = "shared-network"
)

type KernelProbeStatus string

const (
	KernelProbePass    KernelProbeStatus = "PASS"
	KernelProbeWarn    KernelProbeStatus = "WARN"
	KernelProbeFail    KernelProbeStatus = "FAIL"
	KernelProbeUnknown KernelProbeStatus = "UNKNOWN"
)

type KernelProbeImportance string

const (
	KernelProbeRequired    KernelProbeImportance = "required"
	KernelProbePerformance KernelProbeImportance = "performance"
	KernelProbeFallback    KernelProbeImportance = "fallback"
)

type KernelProbeOptions struct {
	Mode          KernelProbeMode
	Network       []string
	CgroupPath    string
	InterfaceName string
}

type KernelProbeFinding struct {
	Status     KernelProbeStatus     `json:"status"`
	Scope      string                `json:"scope"`
	Importance KernelProbeImportance `json:"importance"`
	Feature    string                `json:"feature"`
	Detail     string                `json:"detail"`
}

type KernelProbeProgram struct {
	ID       CiliumEBPF.ProgramID
	Name     string
	Type     CiliumEBPF.ProgramType
	MapCount int
}

type KernelProbeReport struct {
	Platform       string
	KernelRelease  string
	Architecture   string
	Mode           KernelProbeMode
	Network        []string
	Findings       []KernelProbeFinding
	ActivePrograms []KernelProbeProgram
	ActiveStateErr error
}

func (r *KernelProbeReport) Add(
	status KernelProbeStatus,
	scope string,
	importance KernelProbeImportance,
	feature string,
	detail string,
) {
	r.Findings = append(r.Findings, KernelProbeFinding{
		Status:     status,
		Scope:      scope,
		Importance: importance,
		Feature:    feature,
		Detail:     detail,
	})
}

func (r *KernelProbeReport) RequiredFailures() int {
	count := 0
	for _, finding := range r.Findings {
		if finding.Status == KernelProbeFail && finding.Importance == KernelProbeRequired {
			count++
		}
	}
	return count
}

func (r *KernelProbeReport) Counts() map[KernelProbeStatus]int {
	counts := make(map[KernelProbeStatus]int, 4)
	for _, finding := range r.Findings {
		counts[finding.Status]++
	}
	return counts
}

func ProbeKernel(options KernelProbeOptions) (*KernelProbeReport, error) {
	if options.Mode == "" {
		options.Mode = KernelProbeModeAll
	}
	switch options.Mode {
	case KernelProbeModeAll, KernelProbeModeLocal, KernelProbeModeSharedNetwork:
	default:
		return nil, fmt.Errorf("invalid eBPF probe mode: %s", options.Mode)
	}
	enableTCP, enableUDP, network, err := parseKernelProbeNetwork(options.Network)
	if err != nil {
		return nil, err
	}
	memlockErr := raiseMemlockLimit()

	report := &KernelProbeReport{
		Platform:      kernelProbePlatform(),
		KernelRelease: kernelProbeRelease(),
		Architecture:  runtime.GOARCH,
		Mode:          options.Mode,
		Network:       network,
	}
	probeCommonCapabilities(report, memlockErr)
	if options.Mode == KernelProbeModeAll || options.Mode == KernelProbeModeLocal {
		probeLocalCapabilities(report, options.CgroupPath, enableTCP, enableUDP)
	}
	if options.Mode == KernelProbeModeAll || options.Mode == KernelProbeModeSharedNetwork {
		probeSharedNetworkCapabilities(report, options.InterfaceName)
	}
	report.ActivePrograms, report.ActiveStateErr = probeActivePrograms()
	return report, nil
}

func probeCommonCapabilities(report *KernelProbeReport, memlockErr error) {
	if os.Geteuid() == 0 {
		report.Add(KernelProbePass, "common", KernelProbeRequired, "privileged process",
			"The process has UID 0. Direct probes below still detect capability, LSM, or seccomp restrictions.")
	} else {
		report.Add(KernelProbeUnknown, "common", KernelProbeRequired, "BPF and network administration privileges",
			"Run as root or grant the BPF, system-administration, and network-administration capabilities required by the selected data path.")
	}

	version, versionErr := features.LinuxVersionCode()
	if versionErr != nil {
		report.Add(KernelProbeUnknown, "common", KernelProbeRequired, "Linux 4.19 compatibility baseline",
			"The running kernel version could not be read: "+shortProbeError(versionErr))
	} else if version < kernelVersionCode(4, 19, 0) {
		report.Add(KernelProbeFail, "common", KernelProbeRequired, "Linux 4.19 compatibility baseline",
			fmt.Sprintf("The running kernel reports %s; this implementation targets Linux 4.19 or newer.", formatKernelVersionCode(version)))
	} else {
		report.Add(KernelProbePass, "common", KernelProbeRequired, "Linux 4.19 compatibility baseline",
			fmt.Sprintf("The running kernel reports %s. Individual feature probes remain authoritative for vendor kernels.", formatKernelVersionCode(version)))
	}

	probeMapType(report, "common", KernelProbeRequired, CiliumEBPF.Hash,
		"Stores redirect and flow state.")
	probeMapType(report, "common", KernelProbeRequired, CiliumEBPF.Array,
		"Stores runtime controls and counters.")
	probeMapType(report, "common", KernelProbeRequired, CiliumEBPF.LRUHash,
		"Stores bounded socket, UDP, and bypass caches.")
	probeMapType(report, "common", KernelProbeRequired, CiliumEBPF.LPMTrie,
		"Stores UID and CIDR policies. Linux 6.6.0-6.6.46 policy updates remain blocked separately unless the upstream fix is detected.")
	probeMemlockLimit(report, memlockErr)
	probeBPFJIT(report)
}

func probeMemlockLimit(report *KernelProbeReport, raiseErr error) {
	var limit unix.Rlimit
	readErr := unix.Getrlimit(unix.RLIMIT_MEMLOCK, &limit)
	status, detail := memlockProbeResult(limit, readErr, raiseErr)
	report.Add(status, "common", KernelProbeRequired, "locked-memory limit", detail)
}

func memlockProbeResult(limit unix.Rlimit, readErr error, raiseErr error) (KernelProbeStatus, string) {
	if readErr != nil {
		detail := "The process limit could not be read: " + shortProbeError(readErr)
		if raiseErr != nil {
			detail += "; automatic adjustment also failed: " + shortProbeError(raiseErr)
		}
		return KernelProbeUnknown, detail
	}
	if limit.Cur == unix.RLIM_INFINITY {
		return KernelProbePass, "RLIMIT_MEMLOCK is unlimited after automatic adjustment."
	}
	detail := fmt.Sprintf(
		"Automatic adjustment left RLIMIT_MEMLOCK at soft=%d, hard=%d bytes.",
		limit.Cur,
		limit.Max,
	)
	if raiseErr != nil {
		detail += " Adjustment failed: " + shortProbeError(raiseErr) + "."
	}
	detail += " EPERM from subsequent BPF probes may be inconclusive on kernels that charge BPF objects against this limit."
	return KernelProbeWarn, detail
}

func probeLocalCapabilities(report *KernelProbeReport, configuredPath string, enableTCP bool, enableUDP bool) {
	const scope = "local"
	probeCgroupPath(report, configuredPath)
	probeProgramType(report, scope, KernelProbeRequired, CiliumEBPF.CGroupSockAddr,
		"Implements TCP connect interception and UDP sendmsg/recvmsg address translation.")

	connectDetail := "Required for local TCP."
	if !enableTCP {
		connectDetail = "Required for connected local UDP."
	}
	for _, attach := range []struct {
		attach CiliumEBPF.AttachType
		name   string
		detail string
	}{
		{CiliumEBPF.AttachCGroupInet4Connect, "cgroup connect4 attach type", connectDetail},
		{CiliumEBPF.AttachCGroupInet6Connect, "cgroup connect6 attach type", connectDetail + " Also covers IPv4-mapped dual-stack sockets."},
	} {
		probeAttachType(report, scope, KernelProbeRequired, CiliumEBPF.CGroupSockAddr, attach.attach, attach.name, attach.detail)
	}
	if enableUDP {
		for _, attach := range []struct {
			attach CiliumEBPF.AttachType
			name   string
			detail string
		}{
			{CiliumEBPF.AttachCGroupUDP4Sendmsg, "cgroup UDP4 sendmsg attach type", "Required to redirect unconnected IPv4 UDP."},
			{CiliumEBPF.AttachCGroupUDP6Sendmsg, "cgroup UDP6 sendmsg attach type", "Required to redirect unconnected IPv6 and IPv4-mapped UDP."},
			{CiliumEBPF.AttachCGroupUDP4Recvmsg, "cgroup UDP4 recvmsg attach type", "Required to restore the original IPv4 UDP peer. Upstream Linux added recvmsg hooks in 5.2."},
			{CiliumEBPF.AttachCGroupUDP6Recvmsg, "cgroup UDP6 recvmsg attach type", "Required to restore the original IPv6 or IPv4-mapped UDP peer. Upstream Linux added recvmsg hooks in 5.2."},
		} {
			probeAttachType(report, scope, KernelProbeRequired, CiliumEBPF.CGroupSockAddr, attach.attach, attach.name, attach.detail)
		}
	}

	for _, helper := range []struct {
		fn     asm.BuiltinFunc
		name   string
		detail string
	}{
		{asm.FnMapLookupElem, "bpf_map_lookup_elem", "Reads policy, protection, redirect, and UDP state."},
		{asm.FnMapUpdateElem, "bpf_map_update_elem", "Creates redirect, token, peer, and flow state."},
		{asm.FnMapDeleteElem, "bpf_map_delete_elem", "Reclaims or replaces UDP state."},
		{asm.FnGetSocketCookie, "bpf_get_socket_cookie", "Identifies sockets and enforces sing-box self-protection."},
		{asm.FnGetCurrentUidGid, "bpf_get_current_uid_gid", "Enforces UID and Android package policy when configured."},
		{asm.FnKtimeGetNs, "bpf_ktime_get_ns", "Timestamps TCP redirect state."},
	} {
		probeProgramHelper(report, scope, KernelProbeRequired, CiliumEBPF.CGroupSockAddr, helper.fn, helper.name, helper.detail)
	}
	if enableUDP {
		probeAttachType(report, scope, KernelProbeFallback, CiliumEBPF.CGroupSock,
			CiliumEBPF.AttachCgroupInetSockRelease, "cgroup inet_sock_release attach type",
			"Enables exact connected-UDP cleanup. Bounded LRU maps and a reduced UDP cache are used when unavailable.")
	}
}

func probeSharedNetworkCapabilities(report *KernelProbeReport, interfaceName string) {
	const scope = "shared-network"
	probeProgramType(report, scope, KernelProbeRequired, CiliumEBPF.SchedCLS,
		"Implements TC ingress and egress interception, policy, token rewriting, and reply restoration.")
	probeMapType(report, scope, KernelProbeRequired, CiliumEBPF.PerCPUArray,
		"Provides lock-free per-CPU packet parsing scratch space.")
	probeAttachType(report, scope, KernelProbePerformance, CiliumEBPF.SchedCLS,
		CiliumEBPF.AttachTCXIngress, "TCX ingress attach type",
		"Used on modern kernels for qdisc-independent ingress attachment; clsact is the fallback.")
	probeAttachType(report, scope, KernelProbePerformance, CiliumEBPF.SchedCLS,
		CiliumEBPF.AttachTCXEgress, "TCX egress attach type",
		"Used on modern kernels for qdisc-independent egress attachment; clsact is the fallback.")

	for _, helper := range []struct {
		fn     asm.BuiltinFunc
		name   string
		detail string
	}{
		{asm.FnMapLookupElem, "bpf_map_lookup_elem", "Reads controls, policy, and flow state."},
		{asm.FnMapUpdateElem, "bpf_map_update_elem", "Creates proxy, reply, and bypass state."},
		{asm.FnMapDeleteElem, "bpf_map_delete_elem", "Removes expired or conflicting flow state."},
		{asm.FnKtimeGetNs, "bpf_ktime_get_ns", "Applies UDP, TCP, and bypass cache lifetimes."},
		{asm.FnSkbPullData, "bpf_skb_pull_data", "Makes packet headers linear and writable."},
		{asm.FnSkbStoreBytes, "bpf_skb_store_bytes", "Rewrites token and original addresses and ports."},
		{asm.FnCsumDiff, "bpf_csum_diff", "Calculates IPv4 and IPv6 checksum deltas."},
		{asm.FnL3CsumReplace, "bpf_l3_csum_replace", "Updates the IPv4 header checksum."},
		{asm.FnL4CsumReplace, "bpf_l4_csum_replace", "Updates TCP and UDP checksums."},
	} {
		probeProgramHelper(report, scope, KernelProbeRequired, CiliumEBPF.SchedCLS, helper.fn, helper.name, helper.detail)
	}
	probeSharedInterface(report, interfaceName)
}

func probeMapType(
	report *KernelProbeReport,
	scope string,
	importance KernelProbeImportance,
	mapType CiliumEBPF.MapType,
	detail string,
) {
	reportFeatureResult(report, scope, importance, "BPF map type "+mapType.String(), detail, features.HaveMapType(mapType))
}

func probeProgramType(
	report *KernelProbeReport,
	scope string,
	importance KernelProbeImportance,
	programType CiliumEBPF.ProgramType,
	detail string,
) {
	reportFeatureResult(report, scope, importance, "BPF program type "+programType.String(), detail, features.HaveProgramType(programType))
}

func probeProgramHelper(
	report *KernelProbeReport,
	scope string,
	importance KernelProbeImportance,
	programType CiliumEBPF.ProgramType,
	helper asm.BuiltinFunc,
	name string,
	detail string,
) {
	reportFeatureResult(report, scope, importance, name+" for "+programType.String(), detail,
		features.HaveProgramHelper(programType, helper))
}

func probeAttachType(
	report *KernelProbeReport,
	scope string,
	importance KernelProbeImportance,
	programType CiliumEBPF.ProgramType,
	attachType CiliumEBPF.AttachType,
	name string,
	detail string,
) {
	reportFeatureResult(report, scope, importance, name, detail, haveAttachType(programType, attachType))
}

func haveAttachType(programType CiliumEBPF.ProgramType, attachType CiliumEBPF.AttachType) error {
	program, err := CiliumEBPF.NewProgramWithOptions(&CiliumEBPF.ProgramSpec{
		Type:       programType,
		AttachType: attachType,
		License:    "GPL",
		Instructions: asm.Instructions{
			asm.Mov.Imm(asm.R0, 1),
			asm.Return(),
		},
	}, CiliumEBPF.ProgramOptions{LogDisabled: true})
	if err == nil {
		program.Close()
		return nil
	}
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.E2BIG) || errors.Is(err, unix.EOPNOTSUPP) {
		return CiliumEBPF.ErrNotSupported
	}
	return err
}

func reportFeatureResult(
	report *KernelProbeReport,
	scope string,
	importance KernelProbeImportance,
	feature string,
	detail string,
	err error,
) {
	status := classifyKernelProbeError(err)
	if err != nil && status == KernelProbeUnknown {
		detail += " Probe was inconclusive: " + shortProbeError(err)
	} else if err != nil && importance == KernelProbeFallback {
		status = KernelProbeWarn
		detail += " The documented compatibility fallback will be used."
	}
	report.Add(status, scope, importance, feature, detail)
}

func classifyKernelProbeError(err error) KernelProbeStatus {
	switch {
	case err == nil:
		return KernelProbePass
	case errors.Is(err, CiliumEBPF.ErrNotSupported):
		return KernelProbeFail
	default:
		return KernelProbeUnknown
	}
}

func probeCgroupPath(report *KernelProbeReport, configuredPath string) {
	const scope = "local"
	mountPath, err := DetectCgroup2Mount()
	if err != nil {
		report.Add(KernelProbeFail, scope, KernelProbeRequired, "cgroup v2 mount", err.Error())
		return
	}
	path := configuredPath
	if path == "" {
		path = mountPath
	}
	path = filepath.Clean(path)
	if !pathWithin(path, mountPath) {
		report.Add(KernelProbeFail, scope, KernelProbeRequired, "cgroup v2 path: "+path,
			"The path is not below the detected cgroup v2 mount "+mountPath+".")
		return
	}
	info, err := os.Stat(path)
	if err != nil {
		report.Add(KernelProbeFail, scope, KernelProbeRequired, "cgroup v2 path: "+path,
			"The path cannot be inspected: "+shortProbeError(err))
		return
	}
	if !info.IsDir() {
		report.Add(KernelProbeFail, scope, KernelProbeRequired, "cgroup v2 path: "+path,
			"The configured path is not a directory.")
		return
	}
	var stat unix.Statfs_t
	if err = unix.Statfs(path, &stat); err != nil {
		report.Add(KernelProbeUnknown, scope, KernelProbeRequired, "cgroup v2 path: "+path,
			"The filesystem type cannot be inspected: "+shortProbeError(err))
		return
	}
	if stat.Type != unix.CGROUP2_SUPER_MAGIC {
		report.Add(KernelProbeFail, scope, KernelProbeRequired, "cgroup v2 path: "+path,
			"The path is not on a cgroup v2 filesystem.")
		return
	}
	report.Add(KernelProbePass, scope, KernelProbeRequired, "cgroup v2 path: "+path,
		"Local connect/sendmsg/recvmsg programs can attach to this hierarchy when permitted.")
}

func probeSharedInterface(report *KernelProbeReport, interfaceName string) {
	const scope = "shared-network"
	if interfaceName == "" {
		report.Add(KernelProbeUnknown, scope, KernelProbeRequired, "downstream interface",
			"Pass --interface with one configured shared.interface value to validate its link type and IPv4 route_localnet control.")
		return
	}
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		report.Add(KernelProbeFail, scope, KernelProbeRequired, "interface "+interfaceName,
			"The interface is absent. Android hotspot interfaces may exist only while tethering is enabled: "+shortProbeError(err))
		return
	}
	if len(iface.HardwareAddr) != 6 {
		report.Add(KernelProbeFail, scope, KernelProbeRequired, "Ethernet-like interface "+interfaceName,
			fmt.Sprintf("The interface has a %d-byte hardware address; the TC parser requires Ethernet framing.", len(iface.HardwareAddr)))
	} else {
		report.Add(KernelProbePass, scope, KernelProbeRequired, "Ethernet-like interface "+interfaceName,
			"The interface exposes a 48-bit hardware address compatible with the shared-network parser.")
	}
	routeLocalnet := filepath.Join("/proc/sys/net/ipv4/conf", interfaceName, "route_localnet")
	if err = unix.Access(routeLocalnet, unix.W_OK); err != nil {
		report.Add(KernelProbeFail, scope, KernelProbeRequired, "writable route_localnet for "+interfaceName,
			"IPv4 shared-network redirection needs this sysctl to be writable: "+shortProbeError(err))
	} else {
		report.Add(KernelProbePass, scope, KernelProbeRequired, "writable route_localnet for "+interfaceName,
			"IPv4 token addresses can be routed to the local shared listener.")
	}
}

func probeBPFJIT(report *KernelProbeReport) {
	data, err := os.ReadFile("/proc/sys/net/core/bpf_jit_enable")
	if err != nil {
		report.Add(KernelProbeUnknown, "common", KernelProbePerformance, "BPF JIT",
			"The JIT control is not readable; some kernels enable the JIT without exposing this sysctl.")
		return
	}
	value := strings.TrimSpace(string(data))
	if value == "0" {
		report.Add(KernelProbeWarn, "common", KernelProbePerformance, "BPF JIT",
			"The JIT is disabled; interpreting packet-path programs can substantially reduce throughput.")
		return
	}
	report.Add(KernelProbePass, "common", KernelProbePerformance, "BPF JIT",
		"The kernel reports bpf_jit_enable="+value+".")
}

func probeActivePrograms() ([]KernelProbeProgram, error) {
	var programs []KernelProbeProgram
	var current CiliumEBPF.ProgramID
	for {
		next, err := CiliumEBPF.ProgramGetNextID(current)
		if errors.Is(err, os.ErrNotExist) {
			return programs, nil
		}
		if err != nil {
			return programs, err
		}
		current = next
		program, err := CiliumEBPF.NewProgramFromID(next)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return programs, err
		}
		info, infoErr := program.Info()
		program.Close()
		if infoErr != nil {
			return programs, infoErr
		}
		if !strings.HasPrefix(info.Name, "sb_ebpf_") && !strings.HasPrefix(info.Name, "sb_share_") {
			continue
		}
		mapIDs, _ := info.MapIDs()
		programs = append(programs, KernelProbeProgram{
			ID:       next,
			Name:     info.Name,
			Type:     info.Type,
			MapCount: len(mapIDs),
		})
	}
}

func pathWithin(path string, root string) bool {
	relative, err := filepath.Rel(root, path)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))
}

func parseKernelProbeNetwork(configured []string) (bool, bool, []string, error) {
	if len(configured) == 0 {
		configured = []string{"tcp", "udp"}
	}
	var enableTCP, enableUDP bool
	for _, protocol := range configured {
		switch strings.ToLower(strings.TrimSpace(protocol)) {
		case "tcp":
			enableTCP = true
		case "udp":
			enableUDP = true
		default:
			return false, false, nil, fmt.Errorf("invalid eBPF probe network: %s", protocol)
		}
	}
	network := make([]string, 0, 2)
	if enableTCP {
		network = append(network, "tcp")
	}
	if enableUDP {
		network = append(network, "udp")
	}
	return enableTCP, enableUDP, network, nil
}

func kernelProbePlatform() string {
	if runtime.GOOS == "android" {
		return "Android"
	}
	if _, err := os.Stat("/etc/openwrt_release"); err == nil {
		return "OpenWrt"
	}
	return "Linux"
}

func kernelProbeRelease() string {
	var uname unix.Utsname
	if err := unix.Uname(&uname); err != nil {
		return "unknown"
	}
	return strings.TrimRight(string(uname.Release[:]), "\x00")
}

func kernelVersionCode(major uint32, minor uint32, patch uint32) uint32 {
	if patch > 255 {
		patch = 255
	}
	return major<<16 | minor<<8 | patch
}

func formatKernelVersionCode(version uint32) string {
	return fmt.Sprintf("%d.%d.%d", version>>16, version>>8&0xff, version&0xff)
}

func shortProbeError(err error) string {
	message := strings.ReplaceAll(err.Error(), "\n", " ")
	const limit = 240
	if len(message) > limit {
		return message[:limit] + "..."
	}
	return message
}
