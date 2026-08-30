//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"net"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func acquireTCInterfaceLock(interfaceName string, interfaceIndex int) (*net.UnixConn, error) {
	connection, err := net.ListenUnixgram("unixgram", &net.UnixAddr{
		Name: "@sing-box-ebpf-tc-" + fmt.Sprint(interfaceIndex),
		Net:  "unixgram",
	})
	if err != nil {
		if errors.Is(err, unix.EADDRINUSE) {
			return nil, E.New("interface ", interfaceName, " is already managed by another TC eBPF inbound")
		}
		return nil, E.Cause(err, "lock TC eBPF interface ", interfaceName)
	}
	return connection, nil
}

func attachTCFilter(
	link netlink.Link,
	parent uint32,
	programFD int,
	programName string,
	handle uint16,
	priority uint16,
) (*netlink.BpfFilter, error) {
	if programFD < 0 {
		return nil, E.New("TC eBPF program is unavailable")
	}
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return nil, err
	}
	filterHandle := netlink.MakeHandle(0, handle)
	for _, existing := range filters {
		bpfFilter, isBPF := existing.(*netlink.BpfFilter)
		if isBPF && bpfFilter.Name == programName {
			if err = netlink.FilterDel(existing); err != nil && !errors.Is(err, unix.ENOENT) {
				return nil, err
			}
			continue
		}
		if existing.Attrs().Handle == filterHandle {
			return nil, E.New("TC filter handle conflict on ", link.Attrs().Name)
		}
	}
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: link.Attrs().Index,
			Parent:    parent,
			Handle:    filterHandle,
			Priority:  priority,
			Protocol:  unix.ETH_P_ALL,
		},
		Fd:           programFD,
		Name:         programName,
		DirectAction: true,
	}
	if err = netlink.FilterAdd(filter); err != nil {
		return nil, err
	}
	return filter, nil
}

func tcFilterAttached(
	link netlink.Link,
	parent uint32,
	programName string,
	handle uint16,
	priority uint16,
) (bool, error) {
	filters, err := netlink.FilterList(link, parent)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ESRCH) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	filterHandle := netlink.MakeHandle(0, handle)
	for _, existing := range filters {
		bpfFilter, isBPF := existing.(*netlink.BpfFilter)
		if !isBPF {
			continue
		}
		attributes := bpfFilter.Attrs()
		if attributes.Handle == filterHandle &&
			attributes.Priority == priority &&
			bpfFilter.Name == programName &&
			bpfFilter.DirectAction {
			return true, nil
		}
	}
	return false, nil
}

func detachTCFilter(filter *netlink.BpfFilter) error {
	if filter == nil {
		return nil
	}
	err := netlink.FilterDel(filter)
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	return err
}

func ensureTCClsact(link netlink.Link) error {
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return err
	}
	for _, qdisc := range qdiscs {
		if qdisc.Type() == "clsact" {
			return nil
		}
	}
	qdisc := &netlink.GenericQdisc{
		QdiscAttrs: netlink.QdiscAttrs{
			LinkIndex: link.Attrs().Index,
			Handle:    netlink.MakeHandle(0xffff, 0),
			Parent:    netlink.HANDLE_CLSACT,
		},
		QdiscType: "clsact",
	}
	if err = netlink.QdiscAdd(qdisc); err != nil && !errors.Is(err, unix.EEXIST) {
		return err
	}
	return nil
}

func tcLinkNotFound(err error) bool {
	if errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT) {
		return true
	}
	var linkNotFoundError netlink.LinkNotFoundError
	return errors.As(err, &linkNotFoundError)
}

func tcLinkFraming(link netlink.Link) (commonEBPF.TCLinkFraming, error) {
	if link == nil || link.Attrs() == nil {
		return commonEBPF.TCLinkFramingUnsupported, E.New("invalid TC eBPF interface")
	}
	attributes := link.Attrs()
	framing := commonEBPF.ClassifyTCLinkFraming(attributes.EncapType, len(attributes.HardwareAddr))
	if framing == commonEBPF.TCLinkFramingUnsupported {
		return framing, E.New(
			"TC eBPF interface ", attributes.Name,
			" has unsupported link encapsulation ", attributes.EncapType,
		)
	}
	return framing, nil
}
