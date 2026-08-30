//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"

	"github.com/sagernet/netlink"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/features"
	"golang.org/x/sys/unix"
)

type KernelProbeMode string

const (
	KernelProbeModeAll    KernelProbeMode = "all"
	KernelProbeModeLocal  KernelProbeMode = "local"
	KernelProbeModeShared KernelProbeMode = "shared"
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
)

type KernelProbeOptions struct {
	Mode                KernelProbeMode
	Network             []string
	InterfaceName       string
	EnableIPv6          bool
	NeedProcessTracking bool
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
	IPv6           bool
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

func (r *KernelProbeReport) RequiredUnknowns() int {
	count := 0
	for _, finding := range r.Findings {
		if finding.Status == KernelProbeUnknown && finding.Importance == KernelProbeRequired {
			count++
		}
	}
	return count
}

func (r *KernelProbeReport) RequiredIssues() int {
	return r.RequiredFailures() + r.RequiredUnknowns()
}

func (r *KernelProbeReport) RequiredError() error {
	for _, finding := range r.Findings {
		if finding.Importance != KernelProbeRequired || (finding.Status != KernelProbeFail && finding.Status != KernelProbeUnknown) {
			continue
		}
		return fmt.Errorf("eBPF capability %s: %s (%s)", finding.Status, finding.Feature, finding.Detail)
	}
	return nil
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
	case KernelProbeModeAll, KernelProbeModeLocal, KernelProbeModeShared:
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
		IPv6:          options.EnableIPv6,
	}
	needLocal := options.Mode == KernelProbeModeAll || options.Mode == KernelProbeModeLocal
	probeCommonCapabilities(report, memlockErr, options.EnableIPv6, enableTCP, enableUDP, needLocal, options.NeedProcessTracking)
	if options.Mode == KernelProbeModeAll || options.Mode == KernelProbeModeLocal {
		probeLocalCapabilities(report, enableTCP, enableUDP)
	}
	if options.Mode == KernelProbeModeAll || options.Mode == KernelProbeModeShared {
		probeSharedCapabilities(report, options.InterfaceName)
	}
	report.ActivePrograms, report.ActiveStateErr = probeActivePrograms()
	return report, nil
}

func probeCommonCapabilities(report *KernelProbeReport, memlockErr error, enableIPv6, enableTCP, enableUDP, needLocal, needProcessTracking bool) {
	probeLPMTrieUpdateSafety(report)

	probeMapType(report, "common", KernelProbeRequired, CiliumEBPF.Hash,
		"Stores source MAC and exact host-address policy.")
	probeMapType(report, "common", KernelProbeRequired, CiliumEBPF.Array,
		"Stores runtime controls.")
	probeMapType(report, "common", KernelProbeRequired, CiliumEBPF.LRUHash,
		"Stores bounded original-flow assignment and local socket-cookie metadata.")
	probeMapType(report, "common", KernelProbeRequired, CiliumEBPF.LPMTrie,
		"Stores UID, source CIDR, and destination bypass policies.")
	if enableTCP {
		probeMapType(report, "common", KernelProbePerformance, CiliumEBPF.SockMap,
			"Enables the preferred TCP listener fallback; TC loading falls back to direct socket lookup when unavailable.")
	}
	probeProgramType(report, "common", KernelProbeRequired, CiliumEBPF.SchedCLS,
		"Runs the unified local-egress, shared-ingress, and delivery-ingress TC classifiers.")
	helpers := []struct {
		fn     asm.BuiltinFunc
		name   string
		detail string
	}{
		{asm.FnMapLookupElem, "bpf_map_lookup_elem", "Reads controls, policy, listeners, and assignment state."},
		{asm.FnMapUpdateElem, "bpf_map_update_elem", "Publishes original-flow assignment metadata."},
		{asm.FnMapDeleteElem, "bpf_map_delete_elem", "Removes failed assignments."},
	}
	if needLocal {
		helpers = append(helpers,
			struct {
				fn     asm.BuiltinFunc
				name   string
				detail string
			}{asm.FnRedirect, "bpf_redirect", "Redirects selected local packets into the internal delivery veth."},
			struct {
				fn     asm.BuiltinFunc
				name   string
				detail string
			}{asm.FnSkbStoreBytes, "bpf_skb_store_bytes", "Addresses selected local packets to the internal delivery peer."},
			struct {
				fn     asm.BuiltinFunc
				name   string
				detail string
			}{asm.FnGetSocketCookie, "bpf_get_socket_cookie", "Checks the local socket-cookie self-bypass map."},
		)
	}
	if needLocal {
		probeProgramType(report, "local", KernelProbePerformance, CiliumEBPF.CGroupSock,
			"Automatically registers and releases sing-box socket cookies when its cgroup is exclusive; userspace registration is used otherwise.")
		probeProgramHelper(report, "local", KernelProbePerformance, CiliumEBPF.CGroupSock, asm.FnGetSocketCookie,
			"bpf_get_socket_cookie", "Identifies sockets for the optional cgroup self-bypass tracker.")
		probeProgramHelper(report, "local", KernelProbePerformance, CiliumEBPF.CGroupSock, asm.FnMapUpdateElem,
			"bpf_map_update_elem", "Registers socket cookies in the optional cgroup self-bypass tracker.")
		probeProgramHelper(report, "local", KernelProbePerformance, CiliumEBPF.CGroupSock, asm.FnMapDeleteElem,
			"bpf_map_delete_elem", "Releases socket cookies in the optional cgroup self-bypass tracker.")
	}
	if needLocal && needProcessTracking {
		probeProgramType(report, "local", KernelProbePerformance, CiliumEBPF.CGroupSockAddr,
			"Tracks socket ownership at connect and UDP sendmsg for process-aware routing without a procfs descriptor scan.")
		for _, helper := range []struct {
			fn     asm.BuiltinFunc
			name   string
			detail string
		}{
			{asm.FnGetCurrentPidTgid, "bpf_get_current_pid_tgid", "Records the process that operates the socket."},
			{asm.FnGetCurrentUidGid, "bpf_get_current_uid_gid", "Records the socket process user."},
			{asm.FnGetSocketCookie, "bpf_get_socket_cookie", "Correlates cgroup socket ownership with the TC flow."},
			{asm.FnMapUpdateElem, "bpf_map_update_elem", "Publishes bounded socket ownership state."},
		} {
			probeProgramHelper(report, "local", KernelProbePerformance, CiliumEBPF.CGroupSockAddr,
				helper.fn, helper.name, helper.detail)
		}
	}
	if enableTCP {
		helpers = append(helpers, struct {
			fn     asm.BuiltinFunc
			name   string
			detail string
		}{asm.FnSkcLookupTcp, "bpf_skc_lookup_tcp", "Finds transparent TCP listeners and established sockets."})
	}
	if enableUDP {
		helpers = append(helpers, struct {
			fn     asm.BuiltinFunc
			name   string
			detail string
		}{asm.FnSkLookupUdp, "bpf_sk_lookup_udp", "Finds the transparent UDP listener."})
	}
	if enableTCP || enableUDP {
		helpers = append(helpers, struct {
			fn     asm.BuiltinFunc
			name   string
			detail string
		}{asm.FnSkAssign, "bpf_sk_assign", "Assigns packets to transparent TCP and UDP sockets without rewriting tuples."}, struct {
			fn     asm.BuiltinFunc
			name   string
			detail string
		}{asm.FnSkRelease, "bpf_sk_release", "Releases socket references returned by lookup helpers."})
	}
	if needLocal {
		helpers = append(helpers, struct {
			fn     asm.BuiltinFunc
			name   string
			detail string
		}{asm.FnGetSocketUid, "bpf_get_socket_uid", "Applies configured local UID or Android package policy."}, struct {
			fn     asm.BuiltinFunc
			name   string
			detail string
		}{asm.FnSkbChangeHead, "bpf_skb_change_head", "Adds Ethernet framing when the local interface carries raw IP."})
	}
	for _, helper := range helpers {
		probeProgramHelper(report, "common", KernelProbeRequired, CiliumEBPF.SchedCLS, helper.fn, helper.name, helper.detail)
	}
	probeSocketCapabilities(report, enableIPv6, enableTCP, enableUDP)
	probeNetlinkAccess(report)

	probeMemlockLimit(report, memlockErr)
	probeBPFJIT(report)
}

func probeNetlinkAccess(report *KernelProbeReport) {
	_, err := netlink.LinkList()
	reportFeatureResult(report, "common", KernelProbeRequired, "route netlink access",
		"Reads the links used by TC and policy-routing setup. Write permissions are checked by the real startup operations.", err)
}

func probeLPMTrieUpdateSafety(report *KernelProbeReport) {
	if err := checkLPMTriePolicyCompatibility("policy", 1); err != nil {
		report.Add(KernelProbeFail, "common", KernelProbeRequired, "LPM trie policy updates", err.Error())
		return
	}
	report.Add(KernelProbePass, "common", KernelProbeRequired, "LPM trie policy updates",
		"The running kernel accepted a real LPM trie map update.")
}

func probeSocketCapabilities(report *KernelProbeReport, enableIPv6, enableTCP, enableUDP bool) {
	if enableTCP {
		probeSocketOption(report, "IPv4 transparent TCP sockets", unix.AF_INET, unix.SOCK_STREAM, unix.SOL_IP, unix.IP_TRANSPARENT,
			"Transparent TCP listeners and socket assignment.")
	}
	if enableUDP {
		probeSocketOption(report, "IPv4 transparent UDP sockets", unix.AF_INET, unix.SOCK_DGRAM, unix.SOL_IP, unix.IP_TRANSPARENT,
			"Transparent UDP listeners and reply sockets.")
	}
	if enableUDP {
		probeSocketOption(report, "SO_REUSEADDR socket option", unix.AF_INET, unix.SOCK_DGRAM, unix.SOL_SOCKET, unix.SO_REUSEADDR,
			"Allows transparent UDP reply sockets to bind their original source address.")
		probeSocketOption(report, "IPv4 packet information", unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_IP, unix.IP_PKTINFO,
			"Receives the local address of intercepted UDP packets.")
		probeSocketOption(report, "IPv4 original destination", unix.AF_INET, unix.SOCK_DGRAM, unix.SOL_IP, unix.IP_RECVORIGDSTADDR,
			"Receives the original destination of intercepted UDP packets.")
	}
	if !enableIPv6 {
		return
	}
	if !enableTCP && !enableUDP {
		return
	}
	if enableTCP {
		probeSocketOption(report, "IPv6 transparent TCP sockets", unix.AF_INET6, unix.SOCK_STREAM, unix.SOL_IPV6, unix.IPV6_TRANSPARENT,
			"Transparent IPv6 TCP listeners and socket assignment.")
	}
	if enableUDP {
		probeSocketOption(report, "IPv6 transparent UDP sockets", unix.AF_INET6, unix.SOCK_DGRAM, unix.SOL_IPV6, unix.IPV6_TRANSPARENT,
			"Transparent IPv6 UDP listeners and reply sockets.")
	}
	probeSocketOption(report, "IPv6-only listeners", unix.AF_INET6, unix.SOCK_STREAM, unix.IPPROTO_IPV6, unix.IPV6_V6ONLY,
		"Keeps the IPv6 listener separate from the IPv4 listener.")
	if enableUDP {
		probeSocketOption(report, "IPv6 SO_REUSEADDR socket option", unix.AF_INET6, unix.SOCK_DGRAM, unix.SOL_SOCKET, unix.SO_REUSEADDR,
			"Allows transparent IPv6 UDP reply sockets to bind their original source address.")
		probeSocketOption(report, "IPv6 packet information", unix.AF_INET6, unix.SOCK_DGRAM, unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO,
			"Receives the local address of intercepted IPv6 UDP packets.")
		probeSocketOption(report, "IPv6 original destination", unix.AF_INET6, unix.SOCK_DGRAM, unix.SOL_IPV6, unix.IPV6_RECVORIGDSTADDR,
			"Receives the original destination of intercepted IPv6 UDP packets.")
	}
}

func probeSocketOption(report *KernelProbeReport, feature string, family, socketType, level, option int, detail string) {
	fd, err := unix.Socket(family, socketType|unix.SOCK_CLOEXEC, 0)
	if err == nil {
		err = unix.SetsockoptInt(fd, level, option, 1)
		_ = unix.Close(fd)
	}
	reportFeatureResult(report, "common", KernelProbeRequired, feature, detail, err)
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

func probeLocalCapabilities(report *KernelProbeReport, enableTCP bool, enableUDP bool) {
	const scope = "local"
	protocols := selectedProtocolDetail(enableTCP, enableUDP)
	report.Add(KernelProbePass, scope, KernelProbeRequired, "TC local program facilities", protocols+" use the default-interface egress classifier and internal delivery veth; TC attachment and veth creation are verified during startup.")
}

func probeSharedCapabilities(report *KernelProbeReport, interfaceName string) {
	const scope = "shared"
	report.Add(KernelProbePass, scope, KernelProbeRequired, "TC shared program facilities",
		"Configured downstream interfaces use the ingress classifier and transparent socket assignment; TC attachment is verified during startup.")
	probeSharedInterface(report, interfaceName)
}

func selectedProtocolDetail(enableTCP, enableUDP bool) string {
	switch {
	case enableTCP && enableUDP:
		return "TCP and UDP"
	case enableTCP:
		return "TCP"
	default:
		return "UDP"
	}
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
	}
	report.Add(status, scope, importance, feature, detail)
}

func classifyKernelProbeError(err error) KernelProbeStatus {
	switch {
	case err == nil:
		return KernelProbePass
	case errors.Is(err, CiliumEBPF.ErrNotSupported):
		return KernelProbeFail
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EINVAL),
		errors.Is(err, unix.EOPNOTSUPP), errors.Is(err, unix.ENOPROTOOPT),
		errors.Is(err, linuxErrnoNotSupported):
		return KernelProbeFail
	default:
		return KernelProbeUnknown
	}
}

func probeSharedInterface(report *KernelProbeReport, interfaceName string) {
	const scope = "shared"
	if interfaceName == "" {
		report.Add(KernelProbeWarn, scope, KernelProbePerformance, "downstream interface",
			"Pass --interface with one configured shared.interface value to validate its TC framing.")
		return
	}
	link, err := netlink.LinkByName(interfaceName)
	if err != nil {
		report.Add(KernelProbeWarn, scope, KernelProbePerformance, "interface "+interfaceName,
			"The interface is absent. Android hotspot interfaces may exist only while tethering is enabled: "+shortProbeError(err))
		return
	}
	attributes := link.Attrs()
	framing := ClassifyTCLinkFraming(attributes.EncapType, len(attributes.HardwareAddr))
	if framing == TCLinkFramingUnsupported {
		report.Add(KernelProbeFail, scope, KernelProbeRequired, "TC interface framing "+interfaceName,
			"The interface uses unsupported link encapsulation "+attributes.EncapType+".")
		return
	}
	report.Add(KernelProbePass, scope, KernelProbeRequired, "TC interface framing "+interfaceName,
		"The interface uses supported "+framing.String()+" framing ("+attributes.EncapType+").")
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
		if !strings.HasPrefix(info.Name, "sb_tc_") && !strings.HasPrefix(info.Name, "sb_self_") {
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

func shortProbeError(err error) string {
	message := strings.ReplaceAll(err.Error(), "\n", " ")
	const limit = 240
	if len(message) > limit {
		return message[:limit] + "..."
	}
	return message
}
