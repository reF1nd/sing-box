//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

func normalizeEnablement(localOption, sharedOption *bool) (bool, bool, error) {
	if localOption != nil || sharedOption != nil {
		localEnabled := localOption != nil && *localOption
		sharedEnabled := sharedOption != nil && *sharedOption
		if !localEnabled && !sharedEnabled {
			return false, false, E.New("local.enabled or shared.enabled must be enabled")
		}
		return localEnabled, sharedEnabled, nil
	}
	return true, false, nil
}

type normalizedDataPlanes struct {
	localEnabled    bool
	localDataPlane  string
	cgroupPath      string
	sharedEnabled   bool
	sharedDataPlane string
}

func normalizeDataPlanes(options option.EBPFInboundOptions) (normalizedDataPlanes, error) {
	localEnabled, sharedEnabled, err := normalizeEnablement(options.Local.Enabled, options.Shared.Enabled)
	if err != nil {
		return normalizedDataPlanes{}, err
	}
	localDataPlane, cgroupPath, err := normalizeLocalDataPlane(options.Local)
	if err != nil {
		return normalizedDataPlanes{}, err
	}
	sharedDataPlane, err := normalizeSharedDataPlane(options.Shared)
	if err != nil {
		return normalizedDataPlanes{}, err
	}
	return normalizedDataPlanes{localEnabled: localEnabled, localDataPlane: localDataPlane, cgroupPath: cgroupPath, sharedEnabled: sharedEnabled, sharedDataPlane: sharedDataPlane}, nil
}

func normalizeSharedDataPlane(options option.EBPFSharedOptions) (string, error) {
	switch options.DataPlane {
	case "", sharedDataPlanePacketRewrite:
		return sharedDataPlanePacketRewrite, nil
	case sharedDataPlaneSocketAssign:
		return sharedDataPlaneSocketAssign, nil
	default:
		return "", E.New("unknown shared.data_plane: ", options.DataPlane)
	}
}

const (
	localDataPlaneTC     = "tc"
	localDataPlaneCgroup = "cgroup"
)

func normalizeLocalDataPlane(options option.EBPFLocalOptions) (string, string, error) {
	dataPlane := options.DataPlane
	if dataPlane == "" {
		dataPlane = localDataPlaneCgroup
	}
	if dataPlane != localDataPlaneTC && dataPlane != localDataPlaneCgroup {
		return "", "", E.New("unknown local.data_plane: ", dataPlane)
	}
	if dataPlane != localDataPlaneCgroup && options.CgroupPath != "" {
		return "", "", E.New("local.cgroup_path requires local.data_plane=cgroup")
	}
	if options.CgroupPath == "" {
		return dataPlane, "", nil
	}
	if !filepath.IsAbs(options.CgroupPath) {
		return "", "", E.New("local.cgroup_path must be absolute")
	}
	return dataPlane, filepath.Clean(options.CgroupPath), nil
}

func validateLocalOptions(enabled bool, options option.EBPFLocalOptions) error {
	if enabled {
		return nil
	}
	if options.DataPlane != "" {
		return E.New("local.data_plane requires local interception")
	}
	if options.CgroupPath != "" {
		return E.New("local.cgroup_path requires local interception")
	}
	if options.DNSMode != "" {
		return E.New("local.dns_mode requires local interception")
	}
	if options.IPv6 != nil {
		return E.New("local.ipv6 requires local interception")
	}
	if options.BypassPrivateAddress != nil {
		return E.New("local.bypass_private_address requires local interception")
	}
	if len(options.IncludeUID) > 0 || len(options.IncludeUIDRange) > 0 ||
		len(options.ExcludeUID) > 0 || len(options.ExcludeUIDRange) > 0 ||
		len(options.IncludeAndroidUser) > 0 || len(options.IncludePackage) > 0 ||
		len(options.ExcludePackage) > 0 || len(options.BypassPort) > 0 || len(options.BypassPortRange) > 0 {
		return E.New("local options require local interception")
	}
	return nil
}

func validateAndroidUIDOptions(goos string, options option.EBPFLocalOptions) error {
	if !hasAndroidUIDOptions(options) {
		return nil
	}
	if goos != "android" {
		return E.New("include_android_user, include_package, and exclude_package are only supported on Android")
	}
	const maxAndroidUserID = (uint64(^uint32(0)-1) - (androidUserRange - 1)) / androidUserRange
	for _, userID := range options.IncludeAndroidUser {
		if userID < 0 || uint64(userID) > maxAndroidUserID {
			return E.New("invalid include_android_user: ", userID)
		}
	}
	return nil
}

func hasAndroidUIDOptions(options option.EBPFLocalOptions) bool {
	return len(options.IncludeAndroidUser) > 0 || len(options.IncludePackage) > 0 || len(options.ExcludePackage) > 0
}

func normalizeDNSMode(mode string) (string, error) {
	switch mode {
	case "", dnsModeRespectPolicy:
		return dnsModeRespectPolicy, nil
	case dnsModeHijack, dnsModeOff:
		return mode, nil
	default:
		return "", E.New("unknown eBPF dns_mode: ", mode)
	}
}

func enabledByDefault(value *bool) bool {
	return value == nil || *value
}

func parseUIDRanges(uidList []uint32, rangeList []string) ([]commonEBPF.UIDRange, error) {
	uidRanges := make([]commonEBPF.UIDRange, 0, len(uidList)+len(rangeList))
	for _, uid := range uidList {
		uidRanges = append(uidRanges, commonEBPF.UIDRange{Start: uid, End: uid})
	}
	for _, uidRange := range rangeList {
		separator := strings.IndexByte(uidRange, ':')
		if separator < 0 {
			return nil, E.New("missing ':' in range: ", uidRange)
		}
		if separator == 0 {
			return nil, E.New("missing range start: ", uidRange)
		}
		if separator == len(uidRange)-1 {
			return nil, E.New("missing range end: ", uidRange)
		}
		start, err := strconv.ParseUint(uidRange[:separator], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range start")
		}
		end, err := strconv.ParseUint(uidRange[separator+1:], 0, 32)
		if err != nil {
			return nil, E.Cause(err, "parse range end")
		}
		if start > end {
			return nil, E.New("range start is greater than range end: ", uidRange)
		}
		uidRanges = append(uidRanges, commonEBPF.UIDRange{Start: uint32(start), End: uint32(end)})
	}
	return uidRanges, nil
}

func validateSharedOptions(enabled bool, options option.EBPFSharedOptions) error {
	if enabled {
		return nil
	}
	if options.DataPlane != "" || options.DNSMode != "" || len(options.Interface) > 0 || options.IPv6 != nil || options.BypassPrivateAddress != nil ||
		len(options.IncludeSourceCIDR) > 0 || len(options.ExcludeSourceCIDR) > 0 ||
		len(options.IncludeMACAddress) > 0 || len(options.ExcludeMACAddress) > 0 ||
		len(options.BypassPort) > 0 || len(options.BypassPortRange) > 0 {
		return E.New("shared options require shared interception")
	}
	return nil
}

func parsePortRanges(name string, ports []uint16, ranges []string) ([]commonEBPF.PortRange, error) {
	result := make([]commonEBPF.PortRange, 0, len(ports)+len(ranges))
	for _, port := range ports {
		if port == 0 {
			return nil, E.New(name, " contains port 0")
		}
		result = append(result, commonEBPF.PortRange{Start: port, End: port})
	}
	for _, value := range ranges {
		separator := strings.IndexByte(value, ':')
		if separator <= 0 || separator == len(value)-1 {
			return nil, E.New(name, " invalid range: ", value)
		}
		start, err := strconv.ParseUint(value[:separator], 10, 16)
		if err != nil || start == 0 {
			return nil, E.New(name, " invalid range start: ", value)
		}
		end, err := strconv.ParseUint(value[separator+1:], 10, 16)
		if err != nil || end == 0 || start > end {
			return nil, E.New(name, " invalid range end: ", value)
		}
		result = append(result, commonEBPF.PortRange{Start: uint16(start), End: uint16(end)})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Start != result[j].Start {
			return result[i].Start < result[j].Start
		}
		return result[i].End < result[j].End
	})
	merged := result[:0]
	for _, current := range result {
		if len(merged) == 0 || uint32(current.Start) > uint32(merged[len(merged)-1].End)+1 {
			merged = append(merged, current)
			continue
		}
		if current.End > merged[len(merged)-1].End {
			merged[len(merged)-1].End = current.End
		}
	}
	return merged, nil
}

func normalizeSharedOptions(options option.EBPFSharedOptions) (option.EBPFSharedOptions, error) {
	if len(options.Interface) == 0 {
		return option.EBPFSharedOptions{}, E.New("shared.interface must not be empty")
	}
	seen := make(map[string]struct{}, len(options.Interface))
	interfaces := make(badoption.Listable[string], 0, len(options.Interface))
	for _, interfaceName := range options.Interface {
		interfaceName = strings.TrimSpace(interfaceName)
		if interfaceName == "" {
			return option.EBPFSharedOptions{}, E.New("shared.interface contains an empty interface name")
		}
		if interfaceName == "lo" {
			return option.EBPFSharedOptions{}, E.New("shared.interface must not contain lo")
		}
		if _, loaded := seen[interfaceName]; loaded {
			continue
		}
		seen[interfaceName] = struct{}{}
		interfaces = append(interfaces, interfaceName)
	}
	options.Interface = interfaces
	var err error
	options.IncludeSourceCIDR, err = normalizeSourceCIDR("include_source_cidr", options.IncludeSourceCIDR)
	if err != nil {
		return option.EBPFSharedOptions{}, err
	}
	options.ExcludeSourceCIDR, err = normalizeSourceCIDR("exclude_source_cidr", options.ExcludeSourceCIDR)
	if err != nil {
		return option.EBPFSharedOptions{}, err
	}
	return options, nil
}

func normalizeSourceCIDR(name string, prefixes []netip.Prefix) (badoption.Listable[netip.Prefix], error) {
	normalized := make(badoption.Listable[netip.Prefix], 0, len(prefixes))
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			return nil, E.New("invalid shared.", name)
		}
		prefix = prefix.Masked()
		if prefix.Addr().Is4In6() && prefix.Bits() >= 96 {
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96).Masked()
		}
		if _, loaded := seen[prefix]; loaded {
			continue
		}
		seen[prefix] = struct{}{}
		normalized = append(normalized, prefix)
	}
	return normalized, nil
}

func parseSharedMACAddresses(name string, addresses []string) ([]commonEBPF.MACAddress, error) {
	parsed := make([]commonEBPF.MACAddress, 0, len(addresses))
	seen := make(map[commonEBPF.MACAddress]struct{}, len(addresses))
	for index, address := range addresses {
		hardwareAddress, err := net.ParseMAC(address)
		if err != nil {
			return nil, E.Cause(err, "parse shared.", name, "[", index, "]")
		}
		if len(hardwareAddress) != len(commonEBPF.MACAddress{}) {
			return nil, E.New("shared.", name, "[", index, "] must be a 48-bit MAC address")
		}
		var mac commonEBPF.MACAddress
		copy(mac[:], hardwareAddress)
		if _, loaded := seen[mac]; loaded {
			continue
		}
		seen[mac] = struct{}{}
		parsed = append(parsed, mac)
	}
	return parsed, nil
}
