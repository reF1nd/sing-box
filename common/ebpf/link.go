//go:build with_ebpf && (linux || android)

package ebpf

type TCLinkFraming uint8

const (
	TCLinkFramingUnsupported TCLinkFraming = iota
	TCLinkFramingEthernet
	TCLinkFramingRawIP
)

func ClassifyTCLinkFraming(encapsulation string, hardwareAddressLength int) TCLinkFraming {
	switch encapsulation {
	case "ether":
		if hardwareAddressLength == 6 {
			return TCLinkFramingEthernet
		}
	// The netlink dependency currently renders Linux ARPHRD_RAWIP (519) as unknown519.
	case "none", "rawip", "unknown519", "ppp", "ipip", "tun":
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
