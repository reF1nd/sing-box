//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json/badoption"
)

func validateCgroupOptions(enabled bool, options option.EBPFInboundOptions) error {
	if enabled {
		return nil
	}
	if options.CgroupPath != "" {
		return E.New("cgroup_path requires cgroup_enabled")
	}
	if options.CgroupIPv6Mode != "" {
		return E.New("cgroup_ipv6_mode requires cgroup_enabled")
	}
	if len(options.IncludeUID) > 0 || len(options.IncludeUIDRange) > 0 ||
		len(options.ExcludeUID) > 0 || len(options.ExcludeUIDRange) > 0 ||
		len(options.IncludeAndroidUser) > 0 || len(options.IncludePackage) > 0 ||
		len(options.ExcludePackage) > 0 {
		return E.New("UID policy requires cgroup_enabled")
	}
	if options.MapCapacity.TCPRedirect != nil ||
		options.MapCapacity.UDPRedirect != nil ||
		options.MapCapacity.SocketBypass != nil {
		return E.New("map_capacity requires cgroup_enabled")
	}
	return nil
}

func validateAndroidUIDOptions(goos string, options option.EBPFInboundOptions) error {
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

func hasAndroidUIDOptions(options option.EBPFInboundOptions) bool {
	return len(options.IncludeAndroidUser) > 0 || len(options.IncludePackage) > 0 || len(options.ExcludePackage) > 0
}

func validateDataPaths(cgroupEnabled bool, sharedNetworkEnabled bool) error {
	if !cgroupEnabled && !sharedNetworkEnabled {
		return E.New("eBPF inbound requires cgroup_enabled or shared_network.enabled")
	}
	return nil
}

func normalizeDNSMode(mode string) (string, error) {
	switch mode {
	case "", dnsModeHijack:
		return dnsModeHijack, nil
	case dnsModeOff:
		return dnsModeOff, nil
	default:
		return "", E.New("unknown eBPF dns_mode: ", mode)
	}
}

func normalizeCgroupIPv6Mode(mode string) (string, error) {
	switch mode {
	case "", cgroupIPv6ModeAlways:
		return cgroupIPv6ModeAlways, nil
	case cgroupIPv6ModeAuto, cgroupIPv6ModeOff:
		return mode, nil
	default:
		return "", E.New("unknown eBPF cgroup_ipv6_mode: ", mode)
	}
}

func validateCgroupAddressFamilies(
	enabled bool,
	ipv6Mode string,
	ipv4Prefix netip.Prefix,
	ipv6Prefix netip.Prefix,
) error {
	if !enabled {
		return nil
	}
	if !ipv4Prefix.IsValid() && (!ipv6Prefix.IsValid() || ipv6Mode == cgroupIPv6ModeOff) {
		return E.New("eBPF local cgroup interception has no enabled address family")
	}
	return nil
}

func normalizeCgroupMapCapacity(options option.EBPFMapCapacityOptions) (ECommon.CgroupMapCapacity, error) {
	capacity := ECommon.DefaultCgroupMapCapacity()
	var err error
	capacity.TCPRedirect, err = normalizeMapCapacityValue(
		"map_capacity.tcp_redirect", options.TCPRedirect, capacity.TCPRedirect,
	)
	if err != nil {
		return ECommon.CgroupMapCapacity{}, err
	}
	capacity.UDPRedirect, err = normalizeMapCapacityValue(
		"map_capacity.udp_redirect", options.UDPRedirect, capacity.UDPRedirect,
	)
	if err != nil {
		return ECommon.CgroupMapCapacity{}, err
	}
	capacity.SocketBypass, err = normalizeMapCapacityValue(
		"map_capacity.socket_bypass", options.SocketBypass, capacity.SocketBypass,
	)
	if err != nil {
		return ECommon.CgroupMapCapacity{}, err
	}
	return capacity, nil
}

func normalizeMapCapacityValue(name string, configured *option.EBPFMapCapacity, defaultValue uint32) (uint32, error) {
	if configured == nil {
		return defaultValue, nil
	}
	value := uint32(*configured)
	if value == 0 || value > ECommon.MaxConfigurableMapCapacity {
		return 0, E.New(
			name,
			" must be between 1 and ",
			ECommon.MaxConfigurableMapCapacity,
		)
	}
	return value, nil
}

func normalizeCgroupPath(cgroupPath string) (string, error) {
	if cgroupPath == "" {
		return "", nil
	}
	if !filepath.IsAbs(cgroupPath) {
		return "", E.New("eBPF cgroup_path must be absolute")
	}
	return filepath.Clean(cgroupPath), nil
}

func normalizeRedirectAddresses(addresses []netip.Prefix) (netip.Prefix, netip.Prefix, error) {
	if len(addresses) == 0 {
		return defaultRedirectIPv4Prefix, netip.Prefix{}, nil
	}
	var ipv4Prefix netip.Prefix
	var ipv6Prefix netip.Prefix
	for _, address := range addresses {
		if !address.IsValid() {
			return netip.Prefix{}, netip.Prefix{}, E.New("invalid eBPF redirect address")
		}
		address = address.Masked()
		if err := ECommon.ValidateRedirectPrefix(address); err != nil {
			return netip.Prefix{}, netip.Prefix{}, err
		}
		switch {
		case address.Addr().Is4():
			if ipv4Prefix.IsValid() {
				return netip.Prefix{}, netip.Prefix{}, E.New("duplicate IPv4 eBPF redirect address")
			}
			ipv4Prefix = address
		case address.Addr().Is6() && !address.Addr().Is4In6():
			if ipv6Prefix.IsValid() {
				return netip.Prefix{}, netip.Prefix{}, E.New("duplicate IPv6 eBPF redirect address")
			}
			ipv6Prefix = address
		default:
			return netip.Prefix{}, netip.Prefix{}, E.New("invalid eBPF redirect address family: ", address)
		}
	}
	return ipv4Prefix, ipv6Prefix, nil
}

func parseUIDRanges(uidList []uint32, rangeList []string) ([]ECommon.UIDRange, error) {
	uidRanges := make([]ECommon.UIDRange, 0, len(uidList)+len(rangeList))
	for _, uid := range uidList {
		uidRanges = append(uidRanges, ECommon.UIDRange{Start: uid, End: uid})
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
		uidRanges = append(uidRanges, ECommon.UIDRange{Start: uint32(start), End: uint32(end)})
	}
	return uidRanges, nil
}

func platformExcludedUIDRanges(goos string) []ECommon.UIDRange {
	if goos != "android" {
		return nil
	}
	return []ECommon.UIDRange{{Start: androidTetheringDNSUID, End: androidTetheringDNSUID}}
}

func normalizeSharedNetworkOptions(options option.EBPFSharedNetworkOptions) (option.EBPFSharedNetworkOptions, error) {
	if !options.Enabled {
		return option.EBPFSharedNetworkOptions{}, nil
	}
	if len(options.IncludeInterface) == 0 {
		return option.EBPFSharedNetworkOptions{}, E.New("shared_network.include_interface must not be empty")
	}
	if options.TCPriority == 0 {
		options.TCPriority = option.EBPFTCPriority(defaultSharedNetworkTCPriority)
	}
	seen := make(map[string]struct{}, len(options.IncludeInterface))
	interfaces := make(badoption.Listable[string], 0, len(options.IncludeInterface))
	for _, interfaceName := range options.IncludeInterface {
		interfaceName = strings.TrimSpace(interfaceName)
		if interfaceName == "" {
			return option.EBPFSharedNetworkOptions{}, E.New("shared_network.include_interface contains an empty interface name")
		}
		if interfaceName == "lo" {
			return option.EBPFSharedNetworkOptions{}, E.New("shared_network.include_interface must not contain lo")
		}
		if _, loaded := seen[interfaceName]; loaded {
			continue
		}
		seen[interfaceName] = struct{}{}
		interfaces = append(interfaces, interfaceName)
	}
	options.IncludeInterface = interfaces
	var err error
	options.IncludeSourceCIDR, err = normalizeSourceCIDR("include_source_cidr", options.IncludeSourceCIDR)
	if err != nil {
		return option.EBPFSharedNetworkOptions{}, err
	}
	options.ExcludeSourceCIDR, err = normalizeSourceCIDR("exclude_source_cidr", options.ExcludeSourceCIDR)
	if err != nil {
		return option.EBPFSharedNetworkOptions{}, err
	}
	return options, nil
}

func normalizeSourceCIDR(name string, prefixes []netip.Prefix) (badoption.Listable[netip.Prefix], error) {
	normalized := make(badoption.Listable[netip.Prefix], 0, len(prefixes))
	seen := make(map[netip.Prefix]struct{}, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			return nil, E.New("invalid shared_network.", name)
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

func validateSharedNetworkProtocols(options option.EBPFSharedNetworkOptions, enableUDP bool, dnsMode string) error {
	if options.Enabled && dnsMode == dnsModeHijack && !enableUDP {
		return E.New("shared_network with dns_mode hijack requires UDP")
	}
	return nil
}
