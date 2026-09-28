//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	"github.com/sagernet/sing-box/option"
)

func TestSocketAssignmentIPv6Selection(t *testing.T) {
	for _, local := range []string{localDataPlaneCgroup, localDataPlaneSocketAssign} {
		for _, shared := range []string{sharedDataPlanePacketRewrite, sharedDataPlaneSocketAssign} {
			for _, localEnabled := range []bool{false, true} {
				for _, sharedEnabled := range []bool{false, true} {
					for _, local6 := range []bool{false, true} {
						for _, shared6 := range []bool{false, true} {
							i := &Inbound{localEnabled: localEnabled, localDataPlane: local, localIPv6: local6,
								sharedEnabled: sharedEnabled, sharedDataPlane: shared, sharedIPv6: shared6}
							want := localEnabled && local == localDataPlaneSocketAssign && local6 || sharedEnabled && shared == sharedDataPlaneSocketAssign && shared6
							if i.socketAssignIPv6Enabled() != want {
								t.Fatal("IPv6 leaked across data planes")
							}
						}
					}
				}
			}
		}
	}
}

func TestLegacyTCNameRequiresMigration(t *testing.T) {
	if _, _, err := normalizeLocalDataPlane(option.EBPFLocalOptions{DataPlane: "tc"}); err == nil {
		t.Fatal("legacy tc name must not silently select a data plane")
	}
}

func TestLocalPolicyDoesNotUpdateSharedRewrite(t *testing.T) {
	i := &Inbound{sharedEnabled: true, sharedDataPlane: sharedDataPlanePacketRewrite}
	i.setSharedRewrite(&sharedRewrite{dataPlane: &testSharedKernelRuntime{backend: &commonEBPF.SharedPacketRewriteBackend{}}})
	// A closed shared backend must not participate in a local transaction.
	if err := i.applyBypassCIDRPolicyLocked(nil); err != nil {
		t.Fatal(err)
	}
	if len(i.policyBackends(false)) != 0 || len(i.policyBackends(true)) != 1 {
		t.Fatal("policy scope targets overlap")
	}
	if i.sharedBypassRules.expectedVersion != 0 || i.sharedBypassRules.inconsistent {
		t.Fatal("local update changed shared state")
	}
}

func TestUnusedUDPNATIsInert(t *testing.T) {
	var service *udpNATService
	service.Purge()
	service.ReleaseSocket(1)
	if err := service.Close(); err != nil {
		t.Fatal(err)
	}
	if service.diagnostics().ActiveSessions != 0 {
		t.Fatal("nil service reports sessions")
	}
}

func TestPolicyTargetsFollowSelectedScope(t *testing.T) {
	for _, local := range []string{localDataPlaneCgroup, localDataPlaneSocketAssign} {
		for _, shared := range []string{sharedDataPlanePacketRewrite, sharedDataPlaneSocketAssign} {
			for _, localEnabled := range []bool{false, true} {
				for _, sharedEnabled := range []bool{false, true} {
					i := &Inbound{localEnabled: localEnabled, localDataPlane: local, sharedEnabled: sharedEnabled, sharedDataPlane: shared}
					i.tcDataPlane = newUnstartedTCRuntime(&commonEBPF.TCBackend{})
					i.setCgroupBackend(&commonEBPF.CgroupBackend{})
					i.setSharedRewrite(&sharedRewrite{dataPlane: &testSharedKernelRuntime{backend: &commonEBPF.SharedPacketRewriteBackend{}}})
					for _, scope := range []bool{false, true} {
						targets := i.policyBackends(scope)
						enabled, want := localEnabled, "cgroup"
						if local == localDataPlaneSocketAssign {
							want = "TC"
						}
						if scope {
							enabled, want = sharedEnabled, "packet_rewrite"
							if shared == sharedDataPlaneSocketAssign {
								want = "TC"
							}
						}
						if !enabled {
							if len(targets) != 0 {
								t.Fatal("disabled scope has policy targets")
							}
							continue
						}
						if len(targets) != 1 || targets[0].name != want {
							t.Fatalf("local=%s shared=%s scope=%v: targets=%v, want %s", local, shared, scope, targets, want)
						}
					}
				}
			}
		}
	}
}
