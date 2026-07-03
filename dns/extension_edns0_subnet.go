package dns

import (
	"net/netip"

	"github.com/miekg/dns"
)

func extractClientSubnet(message *dns.Msg) (netip.Prefix, bool) {
	for _, record := range message.Extra {
		optRecord, isOPT := record.(*dns.OPT)
		if !isOPT {
			continue
		}
		for _, option := range optRecord.Option {
			subnetOption, isSubnet := option.(*dns.EDNS0_SUBNET)
			if !isSubnet {
				continue
			}
			return clientSubnetFromOption(subnetOption)
		}
	}
	return netip.Prefix{}, false
}

func clientSubnetFromOption(option *dns.EDNS0_SUBNET) (netip.Prefix, bool) {
	if option.SourceScope != 0 {
		return netip.Prefix{}, false
	}
	var address netip.Addr
	switch option.Family {
	case 1:
		if option.SourceNetmask > 32 {
			return netip.Prefix{}, false
		}
		addressBytes := option.Address.To4()
		if len(addressBytes) != 4 {
			return netip.Prefix{}, false
		}
		address = netip.AddrFrom4([4]byte(addressBytes))
	case 2:
		if option.SourceNetmask > 128 {
			return netip.Prefix{}, false
		}
		var addressValid bool
		address, addressValid = netip.AddrFromSlice(option.Address)
		if !addressValid || address.Is4() {
			return netip.Prefix{}, false
		}
	default:
		return netip.Prefix{}, false
	}
	return netip.PrefixFrom(address, int(option.SourceNetmask)).Masked(), true
}

func SetClientSubnet(message *dns.Msg, clientSubnet netip.Prefix) *dns.Msg {
	return setClientSubnet(message, clientSubnet, true)
}

func setClientSubnet(message *dns.Msg, clientSubnet netip.Prefix, clone bool) *dns.Msg {
	var (
		optRecord    *dns.OPT
		subnetOption *dns.EDNS0_SUBNET
	)
findExists:
	for _, record := range message.Extra {
		var isOPTRecord bool
		if optRecord, isOPTRecord = record.(*dns.OPT); isOPTRecord {
			for _, option := range optRecord.Option {
				var isEDNS0Subnet bool
				subnetOption, isEDNS0Subnet = option.(*dns.EDNS0_SUBNET)
				if isEDNS0Subnet {
					break findExists
				}
			}
		}
	}
	if optRecord == nil {
		exMessage := *message
		message = &exMessage
		optRecord = &dns.OPT{
			Hdr: dns.RR_Header{
				Name:   ".",
				Rrtype: dns.TypeOPT,
			},
		}
		message.Extra = append(message.Extra, optRecord)
	} else if clone {
		return setClientSubnet(message.Copy(), clientSubnet, false)
	}
	if subnetOption == nil {
		subnetOption = new(dns.EDNS0_SUBNET)
		subnetOption.Code = dns.EDNS0SUBNET
		optRecord.Option = append(optRecord.Option, subnetOption)
	}
	if clientSubnet.Addr().Is4() {
		subnetOption.Family = 1
	} else {
		subnetOption.Family = 2
	}
	subnetOption.SourceNetmask = uint8(clientSubnet.Bits())
	subnetOption.Address = clientSubnet.Addr().AsSlice()
	return message
}
