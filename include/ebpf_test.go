package include

import (
	"context"
	"testing"
	"time"

	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
)

func TestEBPFInboundMinimalOptions(t *testing.T) {
	ctx := Context(context.Background())
	var inboundOptions option.Inbound
	if err := json.UnmarshalContext(ctx, []byte(`{"type":"ebpf","tag":"ebpf-in"}`), &inboundOptions); err != nil {
		t.Fatal(err)
	}
	if inboundOptions.Type != "ebpf" || inboundOptions.Tag != "ebpf-in" {
		t.Fatalf("unexpected inbound header: %+v", inboundOptions)
	}
	if _, loaded := inboundOptions.Options.(*option.EBPFInboundOptions); !loaded {
		t.Fatalf("unexpected eBPF options type: %T", inboundOptions.Options)
	}
}

func TestEBPFInboundRuntimeOptions(t *testing.T) {
	ctx := Context(context.Background())
	var inboundOptions option.Inbound
	if err := json.UnmarshalContext(ctx, []byte(`{
		"type": "ebpf",
		"udp_timeout": "45s",
		"local": { "dns_mode": "off" },
		"network": "tcp"
	}`), &inboundOptions); err != nil {
		t.Fatal(err)
	}
	ebpfOptions, loaded := inboundOptions.Options.(*option.EBPFInboundOptions)
	if !loaded {
		t.Fatalf("unexpected eBPF options type: %T", inboundOptions.Options)
	}
	if time.Duration(ebpfOptions.UDPTimeout) != 45*time.Second {
		t.Fatalf("unexpected UDP timeout: %v", time.Duration(ebpfOptions.UDPTimeout))
	}
	if ebpfOptions.Local.DNSMode != "off" {
		t.Fatalf("unexpected local DNS mode: %s", ebpfOptions.Local.DNSMode)
	}
	network := ebpfOptions.Network.Build()
	if len(network) != 1 || network[0] != "tcp" {
		t.Fatalf("unexpected network: %v", network)
	}
}

func TestEBPFInboundRejectsListenFields(t *testing.T) {
	ctx := Context(context.Background())
	for name, content := range map[string]string{
		"listen":      `{"type":"ebpf","listen":"0.0.0.0"}`,
		"listen_port": `{"type":"ebpf","listen_port":5588}`,
		"detour":      `{"type":"ebpf","detour":"other-in"}`,
	} {
		t.Run(name, func(t *testing.T) {
			var inboundOptions option.Inbound
			if err := json.UnmarshalContext(ctx, []byte(content), &inboundOptions); err == nil {
				t.Fatal("expected removed eBPF listen field to be rejected")
			}
		})
	}
}

func TestEBPFInboundPolicyOptions(t *testing.T) {
	ctx := Context(context.Background())
	var inboundOptions option.Inbound
	if err := json.UnmarshalContext(ctx, []byte(`{
		"type": "ebpf",
		"bypass_rule_set": [
			"geoip-cn"
		],
			"local": { "dns_mode": "respect_policy" }
	}`), &inboundOptions); err != nil {
		t.Fatal(err)
	}
	ebpfOptions, loaded := inboundOptions.Options.(*option.EBPFInboundOptions)
	if !loaded {
		t.Fatalf("unexpected eBPF options type: %T", inboundOptions.Options)
	}
	if ebpfOptions.Local.DNSMode != "respect_policy" {
		t.Fatalf("unexpected policy options: %+v", ebpfOptions)
	}
	if len(ebpfOptions.BypassRuleSet) != 1 || ebpfOptions.BypassRuleSet[0] != "geoip-cn" {
		t.Fatalf("unexpected bypass rule-set: %v", ebpfOptions.BypassRuleSet)
	}
}

func TestEBPFInboundSharedNetworkOptions(t *testing.T) {
	ctx := Context(context.Background())
	var inboundOptions option.Inbound
	if err := json.UnmarshalContext(ctx, []byte(`{
		"type": "ebpf",
		"mode": "hybrid",
		"local": {
			"cgroup_path": "/sys/fs/cgroup/test.slice"
		},
		"shared": {
			"dns_mode": "off",
			"interface": ["wlan2"],
				"ipv6": false
		}
	}`), &inboundOptions); err != nil {
		t.Fatal(err)
	}
	ebpfOptions, loaded := inboundOptions.Options.(*option.EBPFInboundOptions)
	if !loaded {
		t.Fatalf("unexpected eBPF options type: %T", inboundOptions.Options)
	}
	if ebpfOptions.Mode != "hybrid" || ebpfOptions.Local.CgroupPath != "/sys/fs/cgroup/test.slice" ||
		len(ebpfOptions.Shared.Interface) != 1 || ebpfOptions.Shared.Interface[0] != "wlan2" ||
		ebpfOptions.Shared.IPv6 == nil || *ebpfOptions.Shared.IPv6 || ebpfOptions.Shared.DNSMode != "off" {
		t.Fatalf("unexpected eBPF shared-network options: %+v", ebpfOptions)
	}
}

func TestEBPFInboundRejectsLegacyOptions(t *testing.T) {
	ctx := Context(context.Background())
	for name, content := range map[string]string{
		"cgroup_enabled":   `{"type":"ebpf","cgroup_enabled":true}`,
		"redirect_address": `{"type":"ebpf","redirect_address":"127.128.0.0/9"}`,
		"dns_mode":         `{"type":"ebpf","dns_mode":"hijack"}`,
		"shared_network":   `{"type":"ebpf","shared_network":{"enabled":true}}`,
		"map_capacity":     `{"type":"ebpf","map_capacity":{"tcp_redirect":1024}}`,
	} {
		t.Run(name, func(t *testing.T) {
			var inboundOptions option.Inbound
			if err := json.UnmarshalContext(ctx, []byte(content), &inboundOptions); err == nil {
				t.Fatal("expected legacy eBPF option to be rejected")
			}
		})
	}
}
