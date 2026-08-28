//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"net/netip"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

func TestCgroupHostAddressFlags(t *testing.T) {
	backend := &CgroupBackend{
		hostIPv4:   []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
		hostIPv6:   []netip.Prefix{netip.MustParsePrefix("2001:db8::1/128")},
		enableIPv6: true,
	}
	if flags := backend.hostAddressFlags(); flags != cgroupFlagHostIPv4|cgroupFlagHostIPv6 {
		t.Fatalf("unexpected dual-stack host address flags: %d", flags)
	}
	backend.enableIPv6 = false
	if flags := backend.hostAddressFlags(); flags != cgroupFlagHostIPv4 {
		t.Fatalf("unexpected IPv4-only host address flags: %d", flags)
	}
	backend.hostIPv4 = nil
	if flags := backend.hostAddressFlags(); flags != 0 {
		t.Fatalf("unexpected empty host address flags: %d", flags)
	}
}

func TestCgroupUDPMapConfiguration(t *testing.T) {
	capacity := CgroupMapCapacity{UDPRedirect: 128, UDPPeer: 32, UDPFlow: 64}
	for _, testCase := range []struct {
		name                   string
		enableUDP              bool
		socketReleaseSupported bool
		layout                 cgroupUDPMapLayout
	}{
		{"disabled", false, false, cgroupUDPMapLayout{
			cleanupType: CiliumEBPF.Hash, cleanupFlags: bpfFlagNoPrealloc,
			peerType: CiliumEBPF.Hash, peerFlags: bpfFlagNoPrealloc,
			peerCapacity: 1, flowCapacity: 1,
		}},
		{"socket_release", true, true, cgroupUDPMapLayout{
			cleanupType: CiliumEBPF.Hash, cleanupFlags: bpfFlagNoPrealloc,
			peerType: CiliumEBPF.Hash, peerFlags: bpfFlagNoPrealloc,
			peerCapacity: capacity.UDPPeer, flowCapacity: capacity.UDPFlow,
		}},
		{"lru_fallback", true, false, cgroupUDPMapLayout{
			cleanupType:  CiliumEBPF.LRUHash,
			peerType:     CiliumEBPF.LRUHash,
			peerCapacity: capacity.UDPPeer, flowCapacity: 1,
		}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			layout := cgroupUDPMapConfiguration(
				testCase.enableUDP,
				testCase.socketReleaseSupported,
				capacity,
			)
			if layout != testCase.layout {
				t.Fatalf("unexpected UDP map configuration: %+v", layout)
			}
		})
	}
}

func TestSocketReleaseUnavailable(t *testing.T) {
	for _, err := range []error{
		unix.EINVAL,
		unix.ENOTSUP,
		unix.EOPNOTSUPP,
		linuxErrnoNotSupported,
		errors.Join(errors.New("attach socket release"), linuxErrnoNotSupported),
	} {
		if !socketReleaseUnavailable(err) {
			t.Fatalf("expected unavailable error: %v", err)
		}
	}
	if socketReleaseUnavailable(unix.EPERM) {
		t.Fatal("permission error must not be treated as an unavailable attach type")
	}
}

func TestCgroupLinkUnavailable(t *testing.T) {
	for _, err := range []error{
		link.ErrNotSupported,
		unix.EINVAL,
		unix.ENOSYS,
		unix.ENOTSUP,
		unix.EOPNOTSUPP,
		unix.EPERM,
		unix.EACCES,
		linuxErrnoNotSupported,
		errors.Join(errors.New("create cgroup link"), unix.EPERM),
	} {
		if !cgroupLinkUnavailable(err) {
			t.Fatalf("expected cgroup link fallback error: %v", err)
		}
	}
	if cgroupLinkUnavailable(unix.ENOMEM) {
		t.Fatal("resource exhaustion must not trigger legacy attachment fallback")
	}
}

func TestValidateCgroupProgramSet(t *testing.T) {
	backend := &CgroupBackend{runtime: &cgroupRuntime{
		enable_udp:               true,
		socket_release_supported: true,
	}}
	programs := make([]*CiliumEBPF.Program, cgroupProgramCount)
	if err := backend.validateCgroupProgramSet(programs); err == nil {
		t.Fatal("expected missing socket-release program to fail validation")
	}
	programs[cgroupProgramSocketRelease] = new(CiliumEBPF.Program)
	if err := backend.validateCgroupProgramSet(programs); err != nil {
		t.Fatal(err)
	}
	backend.runtime.socket_release_supported = false
	if err := backend.validateCgroupProgramSet(programs); err == nil {
		t.Fatal("expected unexpected socket-release program to fail validation")
	}
	programs[cgroupProgramSocketRelease] = nil
	if err := backend.validateCgroupProgramSet(programs); err != nil {
		t.Fatal(err)
	}
}
