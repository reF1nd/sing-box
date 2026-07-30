//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"net/netip"
	"os"
	"testing"
)

const integrationTestEnv = "SING_BOX_EBPF_INTEGRATION"

func TestBackendProgramLoadIntegration(t *testing.T) {
	if os.Getenv(integrationTestEnv) != "1" {
		t.Skip("set " + integrationTestEnv + "=1 to load eBPF programs")
	}
	if os.Geteuid() != 0 {
		t.Fatal("eBPF integration test requires root")
	}
	for _, hijackDNS := range []bool{true, false} {
		name := "off"
		if hijackDNS {
			name = "hijack"
		}
		t.Run(name, func(t *testing.T) {
			testBackendProgramLoad(t, hijackDNS)
		})
	}
}

func testBackendProgramLoad(t *testing.T, hijackDNS bool) {
	backend, err := Prepare(
		os.Getenv("SING_BOX_EBPF_INTEGRATION_CGROUP"),
		65532,
		true,
		true,
		netip.MustParsePrefix("127.128.0.0/9"),
		netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
		Policy{HijackDNS: hijackDNS},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := backend.Close(); err != nil {
			t.Errorf("close eBPF backend: %v", err)
		}
	})

	programs := backend.AttachedPrograms()
	if !containsProgram(programs, "sb_ebpf_rel (cgroup/sock_release)") {
		t.Fatalf("socket-release program was not built: %v", programs)
	}
	stats, err := backend.RuntimeStats()
	if err != nil {
		t.Fatal(err)
	}
	if stats != (RuntimeStats{}) {
		t.Fatalf("new eBPF backend has non-zero runtime stats: %+v", stats)
	}

	sharedBackend, err := PrepareSharedNetwork(
		backend,
		65531,
		true,
		true,
		netip.MustParsePrefix("127.128.0.0/9"),
		netip.MustParsePrefix("fd53:696e:672d:626f::/64"),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := sharedBackend.Close(); err != nil {
			t.Errorf("close shared-network token backend: %v", err)
		}
	})
	if sharedBackend.IngressProgramFD() < 0 || sharedBackend.EgressProgramFD() < 0 {
		t.Fatal("shared-network token programs were not loaded")
	}
	if hasDNSHijack := sharedBackend.control.Flags&sharedNetworkFlagDNSHijack != 0; hasDNSHijack != hijackDNS {
		t.Fatalf("unexpected shared-network DNS hijack flag: %t", hasDNSHijack)
	}
	if err = sharedBackend.UpdateHostAddresses([]netip.Addr{
		netip.MustParseAddr("192.0.2.1"),
		netip.MustParseAddr("2001:db8::1"),
	}); err != nil {
		t.Fatal(err)
	}
	if err = sharedBackend.Enable(); err != nil {
		t.Fatal(err)
	}
	if err = sharedBackend.Disable(); err != nil {
		t.Fatal(err)
	}

	if os.Getenv("SING_BOX_EBPF_INTEGRATION_ATTACH") == "1" {
		if err = backend.Attach(); err != nil {
			t.Fatal(err)
		}
	}
}

func containsProgram(programs []string, expected string) bool {
	for _, program := range programs {
		if program == expected {
			return true
		}
	}
	return false
}
