//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"strings"
	"testing"

	"github.com/sagernet/netlink"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
)

func TestTCLinkFraming(t *testing.T) {
	for _, testCase := range []struct {
		name        string
		attributes  netlink.LinkAttrs
		wantFraming commonEBPF.TCLinkFraming
		wantError   string
	}{
		{
			name: "Ethernet",
			attributes: netlink.LinkAttrs{
				Name:         "wlan0",
				EncapType:    "ether",
				HardwareAddr: net.HardwareAddr{0x02, 0, 0, 0, 0, 1},
			},
			wantFraming: commonEBPF.TCLinkFramingEthernet,
		},
		{
			name:        "Android raw IP",
			attributes:  netlink.LinkAttrs{Name: "rmnet_data1", EncapType: "unknown519"},
			wantFraming: commonEBPF.TCLinkFramingRawIP,
		},
		{
			name:        "PPP",
			attributes:  netlink.LinkAttrs{Name: "ppp0", EncapType: "ppp"},
			wantFraming: commonEBPF.TCLinkFramingRawIP,
		},
		{
			name:       "unsupported",
			attributes: netlink.LinkAttrs{Name: "lo", EncapType: "loopback"},
			wantError:  "unsupported link encapsulation loopback",
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			link := &netlink.Dummy{LinkAttrs: testCase.attributes}
			framing, err := tcLinkFraming(link)
			if testCase.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), testCase.wantError) {
					t.Fatalf("unexpected error: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if framing != testCase.wantFraming {
				t.Fatalf("unexpected framing: %s != %s", framing, testCase.wantFraming)
			}
		})
	}
}
