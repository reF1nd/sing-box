//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net"
	"os"
	"time"

	"github.com/sagernet/netlink"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

var cgroupIPv6ProbeDestination = net.ParseIP("2001:4860:4860::8888")

const cgroupIPv6StableProbes = 2

var (
	cgroupIPv6ProbeDebounce      = 500 * time.Millisecond
	probeCgroupIPv6AvailableFunc = probeCgroupIPv6Available
)

type cgroupIPv6ProbeState struct {
	timer      *time.Timer
	generation uint64
	candidate  bool
	count      uint8
}

func (i *Inbound) cgroupIPv6Enabled() bool {
	return i.redirectIPv6Prefix.IsValid() && i.cgroupIPv6Mode != cgroupIPv6ModeOff
}

func probeCgroupIPv6Available() (bool, error) {
	uid := uint32(os.Getuid())
	routes, err := netlink.RouteGetWithOptions(
		cgroupIPv6ProbeDestination,
		&netlink.RouteGetOptions{UID: &uid},
	)
	if err != nil && (errors.Is(err, unix.EINVAL) || errors.Is(err, unix.EOPNOTSUPP)) {
		routes, err = netlink.RouteGet(cgroupIPv6ProbeDestination)
	}
	if err != nil {
		if errors.Is(err, unix.ENETUNREACH) || errors.Is(err, unix.EHOSTUNREACH) ||
			errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, E.Cause(err, "probe native IPv6 route")
	}
	for _, route := range routes {
		if routeSupportsNativeIPv6(route) {
			return true, nil
		}
	}
	return false, nil
}

func routeSupportsNativeIPv6(route netlink.Route) bool {
	switch route.Type {
	case unix.RTN_UNREACHABLE, unix.RTN_BLACKHOLE, unix.RTN_PROHIBIT, unix.RTN_THROW:
		return false
	}
	if usableNativeIPv6(route.Src) {
		return true
	}
	if route.LinkIndex <= 0 {
		return false
	}
	link, err := netlink.LinkByIndex(route.LinkIndex)
	if err != nil {
		return false
	}
	addresses, err := netlink.AddrList(link, unix.AF_INET6)
	if err != nil {
		return false
	}
	for _, address := range addresses {
		if address.Flags&(unix.IFA_F_TENTATIVE|unix.IFA_F_DADFAILED) != 0 {
			continue
		}
		if usableNativeIPv6(address.IP) {
			return true
		}
	}
	return false
}

func usableNativeIPv6(address net.IP) bool {
	return address != nil && address.To4() == nil && address.IsGlobalUnicast() &&
		!address.IsLoopback() && !address.IsLinkLocalUnicast()
}

func (i *Inbound) refreshCgroupIPv6Availability(initial bool) error {
	if i.cgroupIPv6Mode != cgroupIPv6ModeAuto || !i.redirectIPv6Prefix.IsValid() {
		return nil
	}
	if !initial {
		if i.cgroupBackendInstance() == nil {
			return nil
		}
		i.scheduleCgroupIPv6ProbeLocked()
		return nil
	}
	available, err := probeCgroupIPv6AvailableFunc()
	if err != nil {
		i.cgroupIPv6Available = true
		i.resetCgroupIPv6ProbeLocked()
		i.logger.Warn("probe eBPF local cgroup IPv6 availability; keeping interception enabled: ", err)
		return nil
	}
	i.cgroupIPv6Available = available
	i.resetCgroupIPv6ProbeLocked()
	return nil
}

func (i *Inbound) scheduleCgroupIPv6ProbeLocked() {
	i.cgroupIPv6Probe.generation++
	generation := i.cgroupIPv6Probe.generation
	i.cgroupIPv6Probe.candidate = false
	i.cgroupIPv6Probe.count = 0
	if i.cgroupIPv6Probe.timer != nil {
		i.cgroupIPv6Probe.timer.Stop()
	}
	i.cgroupIPv6Probe.timer = time.AfterFunc(cgroupIPv6ProbeDebounce, func() {
		i.runCgroupIPv6Probe(generation)
	})
}

func (i *Inbound) runCgroupIPv6Probe(generation uint64) {
	i.lifecycleAccess.Lock()
	defer i.lifecycleAccess.Unlock()
	if generation != i.cgroupIPv6Probe.generation {
		return
	}
	i.cgroupIPv6Probe.timer = nil
	available, err := probeCgroupIPv6AvailableFunc()
	if err != nil {
		i.cgroupIPv6Probe.candidate = false
		i.cgroupIPv6Probe.count = 0
		i.logger.Warn("probe eBPF local cgroup IPv6 availability after network update: ", err)
		return
	}
	if available == i.cgroupIPv6Available {
		i.cgroupIPv6Probe.candidate = false
		i.cgroupIPv6Probe.count = 0
		return
	}
	if i.cgroupIPv6Probe.count == 0 || i.cgroupIPv6Probe.candidate != available {
		i.cgroupIPv6Probe.candidate = available
		i.cgroupIPv6Probe.count = 1
	} else {
		i.cgroupIPv6Probe.count++
	}
	if i.cgroupIPv6Probe.count < cgroupIPv6StableProbes {
		i.cgroupIPv6Probe.timer = time.AfterFunc(cgroupIPv6ProbeDebounce, func() {
			i.runCgroupIPv6Probe(generation)
		})
		return
	}
	backend := i.cgroupBackendInstance()
	if backend == nil {
		return
	}
	changed, err := backend.UpdateIPv6Available(available)
	if err != nil {
		i.logger.Warn("update eBPF local cgroup IPv6 availability after network update: ", err)
		return
	}
	if changed {
		i.cgroupIPv6Available = available
		i.logger.Info("updated eBPF local cgroup IPv6 interception: available=", available)
	}
	i.cgroupIPv6Probe.candidate = false
	i.cgroupIPv6Probe.count = 0
}

func (i *Inbound) resetCgroupIPv6ProbeLocked() {
	i.cgroupIPv6Probe.generation++
	i.cgroupIPv6Probe.candidate = false
	i.cgroupIPv6Probe.count = 0
	if i.cgroupIPv6Probe.timer != nil {
		i.cgroupIPv6Probe.timer.Stop()
		i.cgroupIPv6Probe.timer = nil
	}
}
