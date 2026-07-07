package main

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-snell/snellv4"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/protocol/socks"

	"github.com/stretchr/testify/require"
)

const (
	snellSharedPSK  = "snell-shared-password"
	snellUserPSK    = "snell-user-password"
	snellUserKey    = "alice-key"
	snellUserName   = "alice"
	snellTestDomain = "snell.test"
)

var snellPortCursor atomic.Uint32

func init() {
	snellPortCursor.Store(uint32(os.Getpid()) % 10000)
}

func TestSnellSelf(t *testing.T) {
	testCases := []struct {
		name           string
		version        int
		mode           string
		authentication string
		obfsMode       string
		quicProxy      bool
	}{
		{name: "v5-userkey-http", version: 5, authentication: "userkey", obfsMode: "http", quicProxy: true},
		{name: "v5-psk", version: 5, authentication: "psk", quicProxy: true},
		{name: "v6-userkey-default", version: 6, authentication: "userkey"},
		{name: "v6-psk-default", version: 6, authentication: "psk"},
		{name: "v6-psk-unshaped", version: 6, mode: "unshaped", authentication: "psk"},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			ports := snellFreePorts(t, 7)
			serverPort := ports[0]
			clientPort := ports[1]
			testSnellSelf(t, serverPort, clientPort, testCase.version, testCase.mode, testCase.authentication, testCase.obfsMode, false)
			testSnellTraffic(t, clientPort, ports[2:6])
			if testCase.quicProxy {
				testSnellQUICProxy(t, clientPort, ports[6])
			}
		})
	}
}

func TestSnellUDPDomainMapping(t *testing.T) {
	for _, disableDomainUnmapping := range []bool{false, true} {
		t.Run(F.ToString("disable-domain-unmapping-", disableDomainUnmapping), func(t *testing.T) {
			ports := snellFreePorts(t, 3)
			testSnellSelf(t, ports[0], ports[1], 5, "", "psk", "", disableDomainUnmapping)
			if disableDomainUnmapping {
				testSnellUDPDomainWithExternalClient(t, ports[0], ports[2])
			} else {
				testSnellUDPDomain(t, ports[1], ports[2])
			}
		})
	}
}

func testSnellSelf(t *testing.T, serverPort uint16, clientPort uint16, version int, mode string, authentication string, obfsMode string, udpDisableDomainUnmapping bool) {
	user := option.SnellUser{Name: snellUserName}
	inbound := &option.SnellInboundOptions{
		ListenOptions: option.ListenOptions{
			Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
			ListenPort: serverPort,
		},
		Version:                 version,
		Users:                   []option.SnellUser{user},
		MultiUserAuthentication: authentication,
		ObfsOptions: option.SnellObfsServerOptions{
			ObfsMode: obfsMode,
		},
		V6Options: option.SnellV6Options{Mode: mode},
	}
	outbound := &option.SnellOutboundOptions{
		ServerOptions: option.ServerOptions{
			Server:     "127.0.0.1",
			ServerPort: serverPort,
		},
		Version: version,
		Reuse:   true,
		ObfsOptions: option.SnellObfsClientOptions{
			ObfsMode: obfsMode,
			ObfsHost: "example.com",
		},
		V6Options: option.SnellV6Options{Mode: mode},
	}
	if authentication == "psk" {
		inbound.Users[0].PSK = snellUserPSK
		outbound.PSK = snellUserPSK
	} else {
		inbound.PSK = snellSharedPSK
		inbound.Users[0].UserKey = snellUserKey
		outbound.PSK = snellSharedPSK
		outbound.UserKey = snellUserKey
	}
	routeRules := []option.Rule{
		{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: option.RawDefaultRule{Inbound: []string{"mixed-in"}},
				RuleAction: option.RuleAction{
					Action:       C.RuleActionTypeRoute,
					RouteOptions: option.RouteActionOptions{Outbound: "snell-out"},
				},
			},
		},
	}
	snellRuleMatch := option.RawDefaultRule{
		Inbound:  []string{"snell-in"},
		AuthUser: []string{snellUserName},
	}
	if udpDisableDomainUnmapping {
		routeRules = append(routeRules, option.Rule{
			Type: C.RuleTypeDefault,
			DefaultOptions: option.DefaultRule{
				RawDefaultRule: snellRuleMatch,
				RuleAction: option.RuleAction{
					Action: C.RuleActionTypeResolve,
					ResolveOptions: option.RouteActionResolve{
						Server: "snell-test-hosts",
					},
				},
			},
		})
	}
	routeRules = append(routeRules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: snellRuleMatch,
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeRoute,
				RouteOptions: option.RouteActionOptions{
					Outbound: "direct",
					RawRouteOptionsActionOptions: option.RawRouteOptionsActionOptions{
						UDPDisableDomainUnmapping: udpDisableDomainUnmapping,
					},
				},
			},
		},
	})
	startInstance(t, option.Options{
		DNS: snellTestDNSOptions(),
		Inbounds: []option.Inbound{
			{
				Type: C.TypeMixed,
				Tag:  "mixed-in",
				Options: &option.HTTPMixedInboundOptions{
					ListenOptions: option.ListenOptions{
						Listen:     common.Ptr(badoption.Addr(netip.IPv4Unspecified())),
						ListenPort: clientPort,
					},
				},
			},
			{
				Type:    C.TypeSnell,
				Tag:     "snell-in",
				Options: inbound,
			},
		},
		Outbounds: []option.Outbound{
			{Type: C.TypeDirect, Tag: "direct"},
			{Type: C.TypeSnell, Tag: "snell-out", Options: outbound},
		},
		Route: &option.RouteOptions{
			Rules: routeRules,
		},
	})
}

func snellTestDNSOptions() *option.DNSOptions {
	predefined := new(badjson.TypedMap[string, option.HostsDNSPredefinedValue])
	predefined.Put(snellTestDomain, option.HostsDNSPredefinedValue{Addresses: []netip.Addr{netip.AddrFrom4([4]byte{127, 0, 0, 1})}})
	return &option.DNSOptions{RawDNSOptions: option.RawDNSOptions{
		Servers: []option.DNSServerOptions{{
			Type: C.DNSTypeHosts,
			Tag:  "snell-test-hosts",
			Options: &option.HostsDNSServerOptions{
				Predefined: predefined,
			},
		}},
		Final: "snell-test-hosts",
	}}
}

func testSnellTraffic(t *testing.T, proxyPort uint16, destinationPorts []uint16) {
	t.Helper()
	require.Len(t, destinationPorts, 4)
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", proxyPort), socks.Version5, "", "")
	dialTCP := func(port uint16) func() (net.Conn, error) {
		return func() (net.Conn, error) {
			return dialer.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", port))
		}
	}
	dialUDP := func(port uint16) func() (net.PacketConn, error) {
		return func() (net.PacketConn, error) {
			return dialer.ListenPacket(context.Background(), M.ParseSocksaddrHostPort("127.0.0.1", port))
		}
	}
	require.NoError(t, testPingPongWithConn(t, destinationPorts[0], dialTCP(destinationPorts[0])))
	require.NoError(t, testPingPongWithPacketConn(t, destinationPorts[1], dialUDP(destinationPorts[1])))
	require.NoError(t, testPingPongWithConn(t, destinationPorts[2], dialTCP(destinationPorts[2])))
	require.NoError(t, testPingPongWithPacketConn(t, destinationPorts[3], dialUDP(destinationPorts[3])))
}

func snellFreePorts(t *testing.T, count int) []uint16 {
	t.Helper()
	loopback := net.IPv4(127, 0, 0, 1)
	ports := make([]uint16, 0, count)
	var tcpListeners []*net.TCPListener
	var udpListeners []*net.UDPConn
	defer func() {
		for _, listener := range udpListeners {
			require.NoError(t, listener.Close())
		}
		for _, listener := range tcpListeners {
			require.NoError(t, listener.Close())
		}
	}()
	for len(ports) < count {
		port := uint16(20000 + snellPortCursor.Add(1)%10000)
		tcpListener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: loopback, Port: int(port)})
		if err != nil {
			continue
		}
		udpListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: loopback, Port: int(port)})
		if err != nil {
			require.NoError(t, tcpListener.Close())
			continue
		}
		tcpListeners = append(tcpListeners, tcpListener)
		udpListeners = append(udpListeners, udpListener)
		ports = append(ports, port)
	}
	return ports
}

func testSnellQUICProxy(t *testing.T, proxyPort uint16, destinationPort uint16) {
	server, err := listenPacket(N.NetworkUDP, ":"+F.ToString(destinationPort))
	require.NoError(t, err)
	defer server.Close()
	serverDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		n, source, readErr := server.ReadFrom(buffer)
		if readErr == nil {
			_, readErr = server.WriteTo(buffer[:n], source)
		}
		serverDone <- readErr
	}()
	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", proxyPort), socks.Version5, "", "")
	destination := M.ParseSocksaddrHostPort(snellTestDomain, destinationPort)
	packetConn, err := dialer.ListenPacket(context.Background(), M.Socksaddr{})
	require.NoError(t, err)
	defer packetConn.Close()
	require.NoError(t, packetConn.SetDeadline(time.Now().Add(10*time.Second)))
	payload := []byte{0xc0, 0x00, 0x00, 0x00, 0x01}
	_, err = packetConn.WriteTo(payload, destination)
	require.NoError(t, err)
	packetReader, loaded := packetConn.(N.PacketReader)
	require.True(t, loaded)
	response := buf.NewSize(2048)
	defer response.Release()
	source, err := packetReader.ReadPacket(response)
	require.NoError(t, err)
	require.Equal(t, payload, response.Bytes())
	require.Equal(t, destination, source)
	require.NoError(t, <-serverDone)
}

func testSnellUDPDomain(t *testing.T, proxyPort uint16, destinationPort uint16) {
	t.Helper()
	server, err := listenPacket(N.NetworkUDP, ":"+F.ToString(destinationPort))
	require.NoError(t, err)
	defer server.Close()
	serverDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		n, source, readErr := server.ReadFrom(buffer)
		if readErr == nil {
			_, readErr = server.WriteTo(buffer[:n], source)
		}
		serverDone <- readErr
	}()

	dialer := socks.NewClient(N.SystemDialer, M.ParseSocksaddrHostPort("127.0.0.1", proxyPort), socks.Version5, "", "")
	destination := M.ParseSocksaddrHostPort(snellTestDomain, destinationPort)
	packetConn, err := dialer.ListenPacket(context.Background(), M.Socksaddr{})
	require.NoError(t, err)
	defer packetConn.Close()
	require.NoError(t, packetConn.SetDeadline(time.Now().Add(10*time.Second)))
	payload := []byte("domain-query")
	_, err = packetConn.WriteTo(payload, destination)
	require.NoError(t, err)
	select {
	case err = <-serverDone:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("domain request did not reach UDP echo server")
	}
	packetReader, loaded := packetConn.(N.PacketReader)
	require.True(t, loaded)
	response := buf.NewSize(2048)
	defer response.Release()
	source, err := packetReader.ReadPacket(response)
	require.NoError(t, err)
	require.Equal(t, payload, response.Bytes())
	require.Equal(t, destinationPort, source.Port)
	require.True(t, source.IsFqdn(), source.String())
	require.Equal(t, destination.Fqdn, source.Fqdn)
}

func testSnellUDPDomainWithExternalClient(t *testing.T, serverPort uint16, destinationPort uint16) {
	t.Helper()
	server, err := listenPacket(N.NetworkUDP, ":"+F.ToString(destinationPort))
	require.NoError(t, err)
	defer server.Close()
	serverDone := make(chan error, 1)
	go func() {
		buffer := make([]byte, 2048)
		n, source, readErr := server.ReadFrom(buffer)
		if readErr == nil {
			_, readErr = server.WriteTo(buffer[:n], source)
		}
		serverDone <- readErr
	}()

	rawConn, err := N.SystemDialer.DialContext(context.Background(), N.NetworkTCP, M.ParseSocksaddrHostPort("127.0.0.1", serverPort))
	require.NoError(t, err)
	client, err := snellv4.NewClient(snellv4.ClientOptions{PSK: []byte(snellUserPSK)})
	require.NoError(t, err)
	t.Cleanup(func() { client.Close() })
	packetConn, err := client.DialPacketConn(rawConn)
	require.NoError(t, err)
	defer packetConn.Close()
	require.NoError(t, packetConn.SetDeadline(time.Now().Add(10*time.Second)))
	payload := []byte("domain-query")
	request := buf.NewSize(64 + len(payload))
	request.Resize(64, 0)
	_, err = request.Write(payload)
	require.NoError(t, err)
	destination := M.ParseSocksaddrHostPort(snellTestDomain, destinationPort)
	require.NoError(t, packetConn.WritePacket(request, destination))
	select {
	case err = <-serverDone:
		require.NoError(t, err)
	case <-time.After(10 * time.Second):
		t.Fatal("domain request did not reach UDP echo server")
	}
	response := buf.NewSize(2048)
	defer response.Release()
	source, err := packetConn.ReadPacket(response)
	require.NoError(t, err)
	require.Equal(t, payload, response.Bytes())
	require.Equal(t, M.ParseSocksaddrHostPort("127.0.0.1", destinationPort), source)
}
