//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"
)

func TestNetworkStateChanged(t *testing.T) {
	inbound := new(Inbound)
	addresses := []netip.Addr{netip.MustParseAddr("192.0.2.10")}
	interfaces := []string{"br0"}

	if inbound.networkStateChanged("wlan0", addresses, interfaces) {
		t.Fatal("initial network state must not be considered changed")
	}
	if inbound.networkStateChanged("wlan0", addresses, interfaces) {
		t.Fatal("unchanged network state must not be considered changed")
	}
	if !inbound.networkStateChanged("rmnet0", addresses, interfaces) {
		t.Fatal("default interface change must be considered changed")
	}
	if !inbound.networkStateChanged("rmnet0", []netip.Addr{netip.MustParseAddr("198.51.100.10")}, interfaces) {
		t.Fatal("host address change must be considered changed")
	}
	if !inbound.networkStateChanged("rmnet0", []netip.Addr{netip.MustParseAddr("198.51.100.10")}, []string{"br1"}) {
		t.Fatal("shared interface change must be considered changed")
	}
}
