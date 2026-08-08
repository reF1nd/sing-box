//go:build with_ebpf && (linux || android)

package ebpf

import (
	"slices"
	"strings"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/ranges"
)

const androidUserRange = 100000

type androidUIDOptions struct {
	includeAndroidUser []int
	includePackage     []string
	excludePackage     []string
}

func newAndroidUIDOptions(options option.EBPFInboundOptions) *androidUIDOptions {
	if !hasAndroidUIDOptions(options) {
		return nil
	}
	return &androidUIDOptions{
		includeAndroidUser: slices.Clone(options.IncludeAndroidUser),
		includePackage:     slices.Clone(options.IncludePackage),
		excludePackage:     slices.Clone(options.ExcludePackage),
	}
}

func (i *Inbound) resolveAndroidUIDPolicy() error {
	packageManager := i.networkManager.PackageManager()
	if (len(i.androidUIDOptions.includePackage) > 0 || len(i.androidUIDOptions.excludePackage) > 0) && packageManager == nil {
		return E.New("Android package manager is unavailable")
	}
	warnSharedUID := make(map[uint32]struct{})
	i.inspectAndroidPackages(packageManager, "include", i.androidUIDOptions.includePackage, warnSharedUID)
	i.inspectAndroidPackages(packageManager, "exclude", i.androidUIDOptions.excludePackage, warnSharedUID)
	tunOptions := tun.Options{
		IncludeUID:         toTunUIDRanges(i.cgroupPolicy.IncludeUID),
		ExcludeUID:         toTunUIDRanges(i.cgroupPolicy.ExcludeUID),
		IncludeAndroidUser: slices.Clone(i.androidUIDOptions.includeAndroidUser),
		IncludePackage:     slices.Clone(i.androidUIDOptions.includePackage),
		ExcludePackage:     slices.Clone(i.androidUIDOptions.excludePackage),
		Logger:             i.logger,
	}
	tunOptions.BuildAndroidRules(packageManager)
	i.cgroupPolicy.IncludeUID = fromTunUIDRanges(tunOptions.IncludeUID)
	i.cgroupPolicy.ExcludeUID = fromTunUIDRanges(tunOptions.ExcludeUID)
	i.logger.Debug(
		"resolved eBPF Android UID policy at startup: include_ranges=", len(i.cgroupPolicy.IncludeUID),
		", exclude_ranges=", len(i.cgroupPolicy.ExcludeUID),
	)
	return nil
}

func (i *Inbound) inspectAndroidPackages(packageManager tun.PackageManager, mode string, packageNames []string, warnedSharedUID map[uint32]struct{}) {
	for _, packageName := range packageNames {
		packageID, loaded := packageManager.IDBySharedPackage(packageName)
		if !loaded {
			packageID, loaded = packageManager.IDByPackage(packageName)
		}
		if !loaded {
			i.logger.Warn(
				mode, "_package not found at startup: ", packageName,
				"; restart sing-box after the package is installed or its UID changes",
			)
			continue
		}
		if _, warned := warnedSharedUID[packageID]; warned {
			continue
		}
		sharedPackages, loaded := packageManager.PackagesByID(packageID)
		if !loaded || len(sharedPackages) < 2 {
			continue
		}
		warnedSharedUID[packageID] = struct{}{}
		i.logger.Warn(
			"Android packages [", strings.Join(sharedPackages, ", "), "] share UID ", packageID,
			"; eBPF UID policy applies to all of them",
		)
	}
}

func toTunUIDRanges(uidRanges []ECommon.UIDRange) []ranges.Range[uint32] {
	converted := make([]ranges.Range[uint32], 0, len(uidRanges))
	for _, uidRange := range uidRanges {
		converted = append(converted, ranges.New(uidRange.Start, uidRange.End))
	}
	return converted
}

func fromTunUIDRanges(uidRanges []ranges.Range[uint32]) []ECommon.UIDRange {
	converted := make([]ECommon.UIDRange, 0, len(uidRanges))
	for _, uidRange := range uidRanges {
		converted = append(converted, ECommon.UIDRange{Start: uidRange.Start, End: uidRange.End})
	}
	return converted
}
