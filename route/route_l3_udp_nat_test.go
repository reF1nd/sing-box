package route

import (
	"context"
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	R "github.com/sagernet/sing-box/route/rule"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing-tun/gtcpip/header"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestL3UDPDestinationNAT(t *testing.T) {
	client := netip.MustParseAddrPort("192.0.2.1:1234")
	fakeDestination := netip.MustParseAddrPort("198.18.0.1:443")
	realDestination := netip.MustParseAddrPort("203.0.113.1:443")
	portAddress := netip.MustParseAddr("10.0.0.2")
	port := &testL3NATPort{inet4Address: portAddress}
	handler := &testL3NATHandler{
		verdict: tun.FlowVerdict{
			Action:      tun.ActionFlow,
			Port:        port,
			Destination: realDestination,
		},
	}
	writeback := new(testL3NATWriteback)
	dispatcher := tun.NewForwardDispatcher(handler, writeback, log.NewNOPFactory().NewLogger("forward"), 0, 0)
	defer dispatcher.Close()

	request := buildTestIPv4UDPPacket(client, fakeDestination, []byte("request"))
	require.True(t, dispatcher.Dispatch(request))
	dispatcher.Flush()
	require.Len(t, port.writtenPackets, 1)

	forwardIP := header.IPv4(port.writtenPackets[0])
	forwardUDP := header.UDP(forwardIP.Payload())
	require.Equal(t, portAddress, forwardIP.SourceAddr())
	require.Equal(t, realDestination.Addr(), forwardIP.DestinationAddr())
	require.Equal(t, realDestination.Port(), forwardUDP.DestinationPort())
	require.Equal(t, []byte("request"), forwardUDP.Payload())

	require.NotNil(t, port.returnPath)
	replyTarget := netip.AddrPortFrom(portAddress, forwardUDP.SourcePort())
	reply := buildTestIPv4UDPPacket(realDestination, replyTarget, []byte("reply"))
	require.Empty(t, port.returnPath.ReturnPackets([][]byte{reply}))
	require.Len(t, writeback.packets, 1)

	reverseIP := header.IPv4(writeback.packets[0])
	reverseUDP := header.UDP(reverseIP.Payload())
	require.Equal(t, fakeDestination.Addr(), reverseIP.SourceAddr())
	require.Equal(t, client.Addr(), reverseIP.DestinationAddr())
	require.Equal(t, fakeDestination.Port(), reverseUDP.SourcePort())
	require.Equal(t, client.Port(), reverseUDP.DestinationPort())
	require.Equal(t, []byte("reply"), reverseUDP.Payload())
}

func TestL3UDPSniffOverrideDestinationNAT(t *testing.T) {
	client := netip.MustParseAddrPort("192.0.2.1:1234")
	originalDestination := netip.MustParseAddrPort("192.0.2.2:443")
	realDestination := netip.MustParseAddrPort("203.0.113.1:443")
	portAddress := netip.MustParseAddr("10.0.0.2")
	port := &testL3NATPort{inet4Address: portAddress}
	selectedOutbound := &testL3NATFlowOutbound{
		testResolvingFlowOutbound: &testResolvingFlowOutbound{
			testFlowOutbound: &testFlowOutbound{outboundType: "wireguard", tag: "wg"},
			queryOptions:     adapter.DNSQueryOptions{Strategy: C.DomainStrategyIPv4Only},
		},
		port: port,
	}
	dnsRouter := &testL3DNSRouter{addresses: []netip.Addr{realDestination.Addr()}}
	router := &Router{
		ctx:          context.Background(),
		logger:       log.NewNOPFactory().NewLogger("router"),
		outbound:     &testL3OutboundManager{defaultOutbound: selectedOutbound},
		dns:          dnsRouter,
		dnsTransport: new(testL3DNSTransportManager),
		rules: []adapter.Rule{
			&testL3Rule{action: new(R.RuleActionSniffOverrideDestination)},
		},
	}
	handler := &testL3RouterNATHandler{
		router: &testL3SniffHostRouter{
			router:    router,
			sniffHost: "example.com",
		},
	}
	writeback := new(testL3NATWriteback)
	dispatcher := tun.NewForwardDispatcher(handler, writeback, log.NewNOPFactory().NewLogger("forward"), 0, 0)
	defer dispatcher.Close()

	request := buildTestIPv4UDPPacket(client, originalDestination, []byte("request"))
	require.True(t, dispatcher.Dispatch(request))
	dispatcher.Flush()
	require.Equal(t, 1, dnsRouter.lookupCount)
	require.Len(t, port.writtenPackets, 1)

	forwardIP := header.IPv4(port.writtenPackets[0])
	forwardUDP := header.UDP(forwardIP.Payload())
	require.Equal(t, portAddress, forwardIP.SourceAddr())
	require.Equal(t, realDestination.Addr(), forwardIP.DestinationAddr())
	require.Equal(t, realDestination.Port(), forwardUDP.DestinationPort())

	require.NotNil(t, port.returnPath)
	replyTarget := netip.AddrPortFrom(portAddress, forwardUDP.SourcePort())
	reply := buildTestIPv4UDPPacket(realDestination, replyTarget, []byte("reply"))
	require.Empty(t, port.returnPath.ReturnPackets([][]byte{reply}))
	require.Len(t, writeback.packets, 1)

	reverseIP := header.IPv4(writeback.packets[0])
	reverseUDP := header.UDP(reverseIP.Payload())
	require.Equal(t, originalDestination.Addr(), reverseIP.SourceAddr())
	require.Equal(t, client.Addr(), reverseIP.DestinationAddr())
	require.Equal(t, originalDestination.Port(), reverseUDP.SourcePort())
	require.Equal(t, client.Port(), reverseUDP.DestinationPort())
	require.Equal(t, []byte("reply"), reverseUDP.Payload())
}

type testL3SniffHostRouter struct {
	adapter.Router
	router    *Router
	sniffHost string
}

func (r *testL3SniffHostRouter) PreMatch(metadata adapter.InboundContext, firstPacket []byte) adapter.PreMatchResult {
	metadata.SniffHost = r.sniffHost
	return r.router.PreMatch(metadata, firstPacket)
}

type testL3RouterNATHandler struct {
	testL3NATHandler
	router adapter.Router
}

func (h *testL3RouterNATHandler) JudgeFlow(network uint8, source netip.AddrPort, destination netip.AddrPort, firstPacket []byte) tun.FlowVerdict {
	return adapter.JudgeFlow(h.router, "tun-in", C.TypeTun, network, source, destination, firstPacket)
}

type testL3NATFlowOutbound struct {
	*testResolvingFlowOutbound
	port *testL3NATPort
}

func (o *testL3NATFlowOutbound) PortAddresses() (netip.Addr, netip.Addr) {
	return o.port.PortAddresses()
}

func (o *testL3NATFlowOutbound) PortMTU() uint32 {
	return o.port.PortMTU()
}

func (o *testL3NATFlowOutbound) AttachReturn(returnPath tun.Return) error {
	return o.port.AttachReturn(returnPath)
}

func (o *testL3NATFlowOutbound) DetachReturn(returnPath tun.Return) error {
	return o.port.DetachReturn(returnPath)
}

func (o *testL3NATFlowOutbound) WritePackets(packets [][]byte) error {
	return o.port.WritePackets(packets)
}

type testL3NATHandler struct {
	verdict tun.FlowVerdict
}

func (h *testL3NATHandler) JudgeFlow(uint8, netip.AddrPort, netip.AddrPort, []byte) tun.FlowVerdict {
	return h.verdict
}

func (h *testL3NATHandler) NewDNSPacket([]byte, M.Socksaddr, M.Socksaddr, N.PacketWriter) {
}

func (h *testL3NATHandler) NewConnectionEx(context.Context, net.Conn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
}

func (h *testL3NATHandler) NewPacketConnectionEx(context.Context, N.PacketConn, M.Socksaddr, M.Socksaddr, N.CloseHandlerFunc) {
}

type testL3NATPort struct {
	inet4Address   netip.Addr
	returnPath     tun.Return
	writtenPackets [][]byte
}

func (p *testL3NATPort) PortAddresses() (netip.Addr, netip.Addr) {
	return p.inet4Address, netip.Addr{}
}

func (p *testL3NATPort) PortMTU() uint32 {
	return 0
}

func (p *testL3NATPort) AttachReturn(returnPath tun.Return) error {
	p.returnPath = returnPath
	return nil
}

func (p *testL3NATPort) DetachReturn(returnPath tun.Return) error {
	if p.returnPath == returnPath {
		p.returnPath = nil
	}
	return nil
}

func (p *testL3NATPort) WritePackets(packets [][]byte) error {
	p.writtenPackets = append(p.writtenPackets, cloneTestPackets(packets)...)
	return nil
}

type testL3NATWriteback struct {
	packets [][]byte
}

func (w *testL3NATWriteback) ReturnHeadroom() int {
	return 0
}

func (w *testL3NATWriteback) WriteReturnPackets(packets [][]byte) error {
	w.packets = append(w.packets, cloneTestPackets(packets)...)
	return nil
}

func buildTestIPv4UDPPacket(source netip.AddrPort, destination netip.AddrPort, payload []byte) []byte {
	packet := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	ipHeader := header.IPv4(packet)
	ipHeader.Encode(&header.IPv4Fields{
		TotalLength: uint16(len(packet)),
		Protocol:    uint8(header.UDPProtocolNumber),
		TTL:         64,
		SrcAddr:     source.Addr(),
		DstAddr:     destination.Addr(),
	})
	udpHeader := header.UDP(ipHeader.Payload())
	udpHeader.Encode(&header.UDPFields{
		SrcPort: source.Port(),
		DstPort: destination.Port(),
		Length:  uint16(header.UDPMinimumSize + len(payload)),
	})
	copy(udpHeader.Payload(), payload)
	ipHeader.SetChecksum(^ipHeader.CalculateChecksum())
	return packet
}

func cloneTestPackets(packets [][]byte) [][]byte {
	cloned := make([][]byte, len(packets))
	for index, packet := range packets {
		cloned[index] = append([]byte(nil), packet...)
	}
	return cloned
}
