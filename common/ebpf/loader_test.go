//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

type objectMapLayout struct {
	keySize   uint32
	valueSize uint32
}

func TestEmbeddedCgroupObjectLayout(t *testing.T) {
	testEmbeddedObjectLayout(t, loadCgroup, map[string]objectMapLayout{
		"cgroup_control":       {4, 72},
		"cgroup_stats":         {4, 8},
		"cgroup_tcp_redirect":  {20, 40},
		"cgroup_udp_redirect":  {20, 40},
		"cgroup_udp_recovery":  {20, 40},
		"cgroup_udp_token":     {8, 20},
		"cgroup_udp_peer":      {8, 20},
		"cgroup_udp_flow":      {32, 32},
		"cgroup_socket_bypass": {8, 1},
		"cgroup_uid_policy":    {8, 1},
		"cgroup_bypass_ipv4":   {8, 1},
		"cgroup_bypass_ipv6":   {20, 1},
		"cgroup_host_ipv4":     {8, 1},
		"cgroup_host_ipv6":     {20, 1},
	}, []string{
		"cgroup/connect4_cookie",
		"cgroup/connect4_cookie_tcp",
		"cgroup/connect4_cookie_udp",
		"cgroup/sendmsg4_cookie",
		"cgroup/recvmsg4",
		"cgroup/connect6_cookie",
		"cgroup/connect6_cookie_tcp",
		"cgroup/connect6_cookie_udp",
		"cgroup/connect6_mapped_cookie",
		"cgroup/connect6_mapped_cookie_tcp",
		"cgroup/connect6_mapped_cookie_udp",
		"cgroup/sendmsg6_cookie",
		"cgroup/sendmsg6_mapped_cookie",
		"cgroup/recvmsg6",
		"cgroup/recvmsg6_mapped",
		"cgroup/sock_release_cookie",
	})
	assertEmbeddedProgramType(
		t,
		loadCgroup,
		[]string{"cgroup/sock_release_cookie"},
		CiliumEBPF.CGroupSock,
		CiliumEBPF.AttachCgroupInetSockRelease,
	)
}

func TestEmbeddedSharedNetworkObjectLayout(t *testing.T) {
	testEmbeddedObjectLayout(t, loadSharedNetwork, map[string]objectMapLayout{
		"shared_control":             {4, 80},
		"shared_stats":               {4, 8},
		"shared_flow_by_original":    {44, 40},
		"shared_bypass_flow":         {44, 16},
		"shared_flow_by_token":       {40, 40},
		"shared_host_ipv4":           {8, 1},
		"shared_host_ipv6":           {20, 1},
		"shared_include_source_ipv4": {8, 1},
		"shared_include_source_ipv6": {20, 1},
		"shared_exclude_source_ipv4": {8, 1},
		"shared_exclude_source_ipv6": {20, 1},
		"shared_include_source_mac":  {8, 1},
		"shared_exclude_source_mac":  {8, 1},
		"shared_bypass_ipv4":         {8, 1},
		"shared_bypass_ipv6":         {20, 1},
		"shared_scratch":             {4, 192},
	}, []string{
		"classifier/ingress",
		"classifier/egress",
	})
}

func testEmbeddedObjectLayout(
	t *testing.T,
	loadSpec func() (*CiliumEBPF.CollectionSpec, error),
	maps map[string]objectMapLayout,
	sections []string,
) {
	t.Helper()
	spec, err := loadSpec()
	if err != nil {
		t.Fatal(err)
	}
	for name, expected := range maps {
		actual := spec.Maps[name]
		if actual == nil {
			t.Errorf("missing map %q", name)
			continue
		}
		if actual.KeySize != expected.keySize || actual.ValueSize != expected.valueSize {
			t.Errorf(
				"map %q has key/value size %d/%d, want %d/%d",
				name,
				actual.KeySize,
				actual.ValueSize,
				expected.keySize,
				expected.valueSize,
			)
		}
	}
	availableSections := make(map[string]bool, len(spec.Programs))
	for _, program := range spec.Programs {
		availableSections[program.SectionName] = true
	}
	for _, section := range sections {
		if !availableSections[section] {
			t.Errorf("missing program section %q", section)
		}
	}
}

func assertEmbeddedProgramType(
	t *testing.T,
	loadSpec func() (*CiliumEBPF.CollectionSpec, error),
	sections []string,
	programType CiliumEBPF.ProgramType,
	attachType CiliumEBPF.AttachType,
) {
	t.Helper()
	spec, err := loadSpec()
	if err != nil {
		t.Fatal(err)
	}
	expected := make(map[string]bool, len(sections))
	for _, section := range sections {
		expected[section] = false
	}
	for _, program := range spec.Programs {
		if _, selected := expected[program.SectionName]; !selected {
			continue
		}
		expected[program.SectionName] = true
		if program.Type != programType || program.AttachType != attachType {
			t.Errorf(
				"program section %q has type/attach %v/%v, want %v/%v",
				program.SectionName,
				program.Type,
				program.AttachType,
				programType,
				attachType,
			)
		}
	}
	for section, found := range expected {
		if !found {
			t.Errorf("missing program section %q", section)
		}
	}
}
