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

func TestEBPFInboundSharedOptions(t *testing.T) {
	ctx := Context(context.Background())
	var inboundOptions option.Inbound
	if err := json.UnmarshalContext(ctx, []byte(`{
		"type": "ebpf",
		"mode": "hybrid",
		"tc_priority": 7,
		"local": {},
		"shared": {
			"dns_mode": "off",
			"interface": ["wlan2", "rndis0"],
			"ipv6": false
		}
	}`), &inboundOptions); err != nil {
		t.Fatal(err)
	}
	ebpfOptions, loaded := inboundOptions.Options.(*option.EBPFInboundOptions)
	if !loaded {
		t.Fatalf("unexpected eBPF options type: %T", inboundOptions.Options)
	}
	if ebpfOptions.Mode != "hybrid" ||
		ebpfOptions.TCPriority != 7 || len(ebpfOptions.Shared.Interface) != 2 ||
		ebpfOptions.Shared.Interface[0] != "wlan2" || ebpfOptions.Shared.Interface[1] != "rndis0" ||
		ebpfOptions.Shared.IPv6 == nil || *ebpfOptions.Shared.IPv6 || ebpfOptions.Shared.DNSMode != "off" {
		t.Fatalf("unexpected eBPF shared options: %+v", ebpfOptions)
	}
}
