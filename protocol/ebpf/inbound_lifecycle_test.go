//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"testing"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
)

func TestTakeCgroupBackendRetiresCleanupAccess(t *testing.T) {
	backend := &ECommon.CgroupBackend{}
	inbound := &Inbound{}
	inbound.listeners.port = 5300
	inbound.setCgroupBackend(backend)
	if retired := inbound.takeCgroupBackend(); retired != backend {
		t.Fatal("unexpected retired cgroup backend")
	}
	if current := inbound.cgroupBackendInstance(); current != nil {
		t.Fatal("retired cgroup backend remained published")
	}
	inbound.deleteUDPRedirectsWithBackend(backend, []netip.Addr{netip.MustParseAddr("127.128.0.1")})
}

func TestTakeSharedBackend(t *testing.T) {
	backend := &ECommon.SharedNetworkBackend{}
	shared := &sharedNetwork{}
	shared.setSharedBackend(backend)
	if retired := shared.takeSharedBackend(); retired != backend {
		t.Fatal("unexpected retired shared-network backend")
	}
	if current := shared.sharedBackendInstance(); current != nil {
		t.Fatal("retired shared-network backend remained published")
	}
}
