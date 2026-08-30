//go:build with_ebpf && (linux || android)

package ebpf

type TCLinkFraming uint8

const (
	TCLinkFramingUnsupported TCLinkFraming = iota
	TCLinkFramingEthernet
	TCLinkFramingRawIP
)

func ClassifyTCLinkFraming(encapsulation string, _ int) TCLinkFraming {
	switch encapsulation {
	case "ether":
		// ARPHRD_ETHER describes the packet header. Some virtual and vendor
		// links do not expose a six-byte address through netlink, but still
		// carry ordinary Ethernet frames.
		return TCLinkFramingEthernet
	// Keep numeric aliases for netlink versions that do not name every standard
	// L3 ARPHRD value (notably ARPHRD_RAWIP and ARPHRD_IP6GRE).
	case "none", "rawip", "unknown519", "ppp", "ipip", "tunnel6", "sit", "gre", "ip6gre", "tun",
		"slip", "cslip", "slip6", "cslip6", "unknown256", "unknown257", "unknown258", "unknown259",
		"unknown512", "unknown768", "unknown769", "unknown776", "unknown778", "unknown823":
		return TCLinkFramingRawIP
	}
	return TCLinkFramingUnsupported
}

func (f TCLinkFraming) String() string {
	switch f {
	case TCLinkFramingEthernet:
		return "l2"
	case TCLinkFramingRawIP:
		return "l3"
	default:
		return "unsupported"
	}
}
