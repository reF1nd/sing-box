//go:build with_ebpf && (linux || android)

package ebpf

import "testing"

func TestClassifyTCLinkFraming(t *testing.T) {
	for _, testCase := range []struct {
		name                  string
		encapsulation         string
		hardwareAddressLength int
		expected              TCLinkFraming
	}{
		{"Ethernet", "ether", 6, TCLinkFramingEthernet},
		{"invalid Ethernet address", "ether", 0, TCLinkFramingUnsupported},
		{"raw IP", "rawip", 0, TCLinkFramingRawIP},
		{"Android raw IP", "unknown519", 0, TCLinkFramingRawIP},
		{"none", "none", 0, TCLinkFramingRawIP},
		{"PPP", "ppp", 0, TCLinkFramingRawIP},
		{"IPIP", "ipip", 0, TCLinkFramingRawIP},
		{"TUN", "tun", 0, TCLinkFramingRawIP},
		{"loopback", "loopback", 6, TCLinkFramingUnsupported},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			actual := ClassifyTCLinkFraming(testCase.encapsulation, testCase.hardwareAddressLength)
			if actual != testCase.expected {
				t.Fatalf("unexpected framing: %s != %s", actual, testCase.expected)
			}
		})
	}
}
