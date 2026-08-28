//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/sagernet/netlink"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"golang.org/x/sys/unix"
)

func TestUpdateSharedFlowPressure(t *testing.T) {
	usage := ECommon.MapUsage{Capacity: 100}
	active, rounds, entered, exited := updateSharedFlowPressure(false, 0, usage)
	if active || rounds != 0 || entered || exited {
		t.Fatal("empty map unexpectedly entered pressure mode")
	}
	usage.Entries = 70
	active, rounds, entered, exited = updateSharedFlowPressure(active, rounds, usage)
	if !active || !entered || exited {
		t.Fatal("70% map usage did not enter pressure mode")
	}
	usage.Entries = 50
	for expected := 1; expected < sharedFlowPressureExitRounds; expected++ {
		active, rounds, entered, exited = updateSharedFlowPressure(active, rounds, usage)
		if !active || rounds != expected || entered || exited {
			t.Fatalf("unexpected pressure exit state at round %d", expected)
		}
	}
	active, rounds, entered, exited = updateSharedFlowPressure(active, rounds, usage)
	if active || rounds != 0 || entered || !exited {
		t.Fatal("pressure mode did not exit after stable low usage")
	}
}

func TestSharedFlowSweepRequired(t *testing.T) {
	if sharedFlowSweepRequired(sharedFlowSweepInterval-time.Second, false, false, false) {
		t.Fatal("normal shared flow sweep ran early")
	}
	if !sharedFlowSweepRequired(sharedFlowSweepInterval, false, false, false) {
		t.Fatal("normal shared flow sweep did not run on schedule")
	}
	if !sharedFlowSweepRequired(time.Second, true, false, false) {
		t.Fatal("map pressure did not request an early sweep")
	}
	if !sharedFlowSweepRequired(time.Second, false, true, false) {
		t.Fatal("token reservation failure did not request an early sweep")
	}
	if !sharedFlowSweepRequired(time.Second, false, false, true) {
		t.Fatal("incremental scan did not request a continuation")
	}
}

func TestNormalizeSharedNetworkOptions(t *testing.T) {
	options, err := normalizeSharedNetworkOptions(option.EBPFSharedOptions{
		Interface: badoption.Listable[string]{"ap0", " ap0 ", "wlan1"},
		IncludeSourceCIDR: badoption.Listable[netip.Prefix]{
			netip.MustParsePrefix("192.168.43.9/24"),
			netip.MustParsePrefix("192.168.43.0/24"),
			netip.MustParsePrefix("::ffff:192.168.44.1/120"),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(options.Interface) != 2 || options.Interface[0] != "ap0" || options.Interface[1] != "wlan1" {
		t.Fatalf("unexpected interfaces: %v", options.Interface)
	}
	if options.Advanced.TCPriority != defaultSharedNetworkTCPriority {
		t.Fatalf("unexpected default TC priority: %d", options.Advanced.TCPriority)
	}
	wantSourceCIDR := []netip.Prefix{
		netip.MustParsePrefix("192.168.43.0/24"),
		netip.MustParsePrefix("192.168.44.0/24"),
	}
	if len(options.IncludeSourceCIDR) != len(wantSourceCIDR) {
		t.Fatalf("unexpected include source CIDRs: %v", options.IncludeSourceCIDR)
	}
	for index := range wantSourceCIDR {
		if options.IncludeSourceCIDR[index] != wantSourceCIDR[index] {
			t.Fatalf("unexpected include source CIDRs: %v", options.IncludeSourceCIDR)
		}
	}
}

func TestNormalizeSharedNetworkOptionsKeepsTCPriority(t *testing.T) {
	options, err := normalizeSharedNetworkOptions(option.EBPFSharedOptions{
		Interface: []string{"ap0"},
		Advanced: option.EBPFSharedAdvancedOptions{
			TCPriority: 42,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Advanced.TCPriority != 42 {
		t.Fatalf("unexpected TC priority: %d", options.Advanced.TCPriority)
	}
}

func TestNormalizeSharedNetworkOptionsRejectsInvalid(t *testing.T) {
	for _, interfaces := range [][]string{
		nil,
		{""},
		{"lo"},
		{"ap0", "lo"},
	} {
		_, err := normalizeSharedNetworkOptions(option.EBPFSharedOptions{
			Interface: interfaces,
		})
		if err == nil {
			t.Fatalf("expected interfaces to be rejected: %v", interfaces)
		}
	}
	_, err := normalizeSharedNetworkOptions(option.EBPFSharedOptions{
		Interface:         []string{"ap0"},
		IncludeSourceCIDR: []netip.Prefix{{}},
	})
	if err == nil {
		t.Fatal("expected an invalid source CIDR to be rejected")
	}
}

func TestSharedNetworkTCPriorityPrecedesAndroidTethering(t *testing.T) {
	const androidTetheringIPv6Priority = 2
	if defaultSharedNetworkTCPriority >= androidTetheringIPv6Priority {
		t.Fatalf("shared-network TC priority %d does not precede Android IPv6 tethering priority %d",
			defaultSharedNetworkTCPriority, androidTetheringIPv6Priority)
	}
}

func TestSharedTCInterfaceLock(t *testing.T) {
	interfaceIndex := -os.Getpid()
	first, err := acquireSharedTCInterfaceLock("test0", interfaceIndex)
	if err != nil {
		t.Fatal(err)
	}
	second, err := acquireSharedTCInterfaceLock("test0", interfaceIndex)
	if second != nil {
		second.Close()
	}
	if err == nil {
		first.Close()
		t.Fatal("duplicate shared-network interface lock succeeded")
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	third, err := acquireSharedTCInterfaceLock("test0", interfaceIndex)
	if err != nil {
		t.Fatal("released shared-network interface lock was not reusable: ", err)
	}
	if err = third.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestValidateSharedNetworkLink(t *testing.T) {
	valid := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{
		Name:         "ap0",
		HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
	}}
	if err := validateSharedNetworkLink(valid); err != nil {
		t.Fatal(err)
	}
	if err := validateSharedNetworkLink(&netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "tun0"}}); err == nil {
		t.Fatal("expected an interface without an Ethernet address to be rejected")
	}
	if err := validateSharedNetworkLink(nil); err == nil {
		t.Fatal("expected a nil interface to be rejected")
	}
}

func TestSharedTCFilterMatches(t *testing.T) {
	filter := &netlink.BpfFilter{
		FilterAttrs: netlink.FilterAttrs{
			LinkIndex: 7,
			Parent:    netlink.HANDLE_MIN_INGRESS,
			Handle:    netlink.MakeHandle(0, sharedIngressFilterHandle),
			Priority:  defaultSharedNetworkTCPriority,
			Protocol:  unix.ETH_P_ALL,
		},
		Name:         "sb_share_in",
		DirectAction: true,
		Id:           42,
	}
	if !sharedTCFilterMatches(
		filter,
		7,
		netlink.HANDLE_MIN_INGRESS,
		netlink.MakeHandle(0, sharedIngressFilterHandle),
		defaultSharedNetworkTCPriority,
		"sb_share_in",
		42,
	) {
		t.Fatal("expected matching TC filter")
	}
	changedProgram := *filter
	changedProgram.Id = 43
	if sharedTCFilterMatches(
		&changedProgram,
		7,
		netlink.HANDLE_MIN_INGRESS,
		netlink.MakeHandle(0, sharedIngressFilterHandle),
		defaultSharedNetworkTCPriority,
		"sb_share_in",
		42,
	) {
		t.Fatal("accepted a different BPF program")
	}
	changedPriority := *filter
	changedPriority.FilterAttrs.Priority++
	if sharedTCFilterMatches(
		&changedPriority,
		7,
		netlink.HANDLE_MIN_INGRESS,
		netlink.MakeHandle(0, sharedIngressFilterHandle),
		defaultSharedNetworkTCPriority,
		"sb_share_in",
		0,
	) {
		t.Fatal("accepted a different TC priority")
	}
}

func TestSharedTCWaitingSkipsBackendRefresh(t *testing.T) {
	prepareCalls := 0
	manager := &sharedTCManager{
		interfaces: []string{"sbe-missing"},
		prepareBackend: func() (*ECommon.SharedNetworkBackend, error) {
			prepareCalls++
			return nil, nil
		},
		attachments: make(map[string]*sharedTCAttachment),
	}
	if err := manager.reconcile(); err != nil {
		t.Fatal(err)
	}
	if manager.isEnabled() {
		t.Fatal("waiting shared-network manager is enabled")
	}
	if prepareCalls != 0 {
		t.Fatalf("shared-network backend initialized while interface was absent: %d", prepareCalls)
	}
}

func TestSharedTCAttachmentMode(t *testing.T) {
	manager := &sharedTCManager{attachments: map[string]*sharedTCAttachment{
		"tcx0": {tcx: &ECommon.SharedNetworkTCXAttachment{}},
	}}
	if mode := manager.AttachmentModeString(); mode != "tcx" {
		t.Fatalf("unexpected TCX attachment mode: %s", mode)
	}
	manager.attachments["tc0"] = &sharedTCAttachment{}
	if mode := manager.AttachmentModeString(); mode != "mixed" {
		t.Fatalf("unexpected mixed attachment mode: %s", mode)
	}
	delete(manager.attachments, "tcx0")
	if mode := manager.AttachmentModeString(); mode != "clsact" {
		t.Fatalf("unexpected clsact attachment mode: %s", mode)
	}
}

func TestIsSharedNetworkLinkNotFound(t *testing.T) {
	for _, err := range []error{unix.ENOENT, unix.ENODEV} {
		if !isSharedNetworkLinkNotFound(err) {
			t.Fatalf("expected %v to be treated as a missing interface", err)
		}
	}
	_, err := netlink.LinkByName("sbe-not-found")
	if err == nil {
		t.Fatal("expected the test interface to be missing")
	}
	if !isSharedNetworkLinkNotFound(err) {
		t.Fatalf("expected netlink error to be treated as a missing interface: %v", err)
	}
	if isSharedNetworkLinkNotFound(unix.EPERM) {
		t.Fatal("expected a permission error to be retained")
	}
}

func TestSharedNetworkCloseListeners(t *testing.T) {
	shared := &sharedNetwork{
		listeners: internalListenerSet{tcp4: listener.New(listener.Options{})},
	}
	if err := shared.closeListeners(); err != nil {
		t.Fatal(err)
	}
	if err := shared.closeListeners(); err != nil {
		t.Fatal(err)
	}
}
