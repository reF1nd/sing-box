//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"testing"

	"github.com/sagernet/netlink"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json/badoption"

	"golang.org/x/sys/unix"
)

func TestNormalizeSharedNetworkOptions(t *testing.T) {
	options, err := normalizeSharedNetworkOptions(option.EBPFSharedNetworkOptions{
		Enabled:          true,
		IncludeInterface: badoption.Listable[string]{"ap0", " ap0 ", "wlan1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(options.IncludeInterface) != 2 ||
		options.IncludeInterface[0] != "ap0" ||
		options.IncludeInterface[1] != "wlan1" {
		t.Fatalf("unexpected interfaces: %v", options.IncludeInterface)
	}
}

func TestNormalizeSharedNetworkOptionsDisabled(t *testing.T) {
	options, err := normalizeSharedNetworkOptions(option.EBPFSharedNetworkOptions{
		IncludeInterface: badoption.Listable[string]{"wlan1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.Enabled || len(options.IncludeInterface) != 0 {
		t.Fatalf("disabled shared-network options were retained: %+v", options)
	}
}

func TestNormalizeSharedNetworkOptionsRejectsInvalid(t *testing.T) {
	for _, interfaces := range [][]string{
		nil,
		{""},
		{"lo"},
		{"ap0", "lo"},
	} {
		_, err := normalizeSharedNetworkOptions(option.EBPFSharedNetworkOptions{
			Enabled:          true,
			IncludeInterface: interfaces,
		})
		if err == nil {
			t.Fatalf("expected interfaces to be rejected: %v", interfaces)
		}
	}
}

func TestValidateSharedNetworkProtocols(t *testing.T) {
	if err := validateSharedNetworkProtocols(option.EBPFSharedNetworkOptions{}, false, dnsModeHijack); err != nil {
		t.Fatal(err)
	}
	if err := validateSharedNetworkProtocols(option.EBPFSharedNetworkOptions{Enabled: true}, true, dnsModeHijack); err != nil {
		t.Fatal(err)
	}
	if err := validateSharedNetworkProtocols(option.EBPFSharedNetworkOptions{Enabled: true}, false, dnsModeHijack); err == nil {
		t.Fatal("expected shared_network DNS hijacking without UDP to be rejected")
	}
	if err := validateSharedNetworkProtocols(option.EBPFSharedNetworkOptions{Enabled: true}, false, dnsModeOff); err != nil {
		t.Fatalf("shared_network with DNS disabled should allow TCP-only mode: %v", err)
	}
}

func TestSharedNetworkTCPriorityPrecedesAndroidTethering(t *testing.T) {
	const androidTetheringIPv6Priority = 2
	if sharedNetworkTCPriority >= androidTetheringIPv6Priority {
		t.Fatalf("shared-network TC priority %d does not precede Android IPv6 tethering priority %d",
			sharedNetworkTCPriority, androidTetheringIPv6Priority)
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
