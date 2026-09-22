//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestTCPacketWriterBatchesByReplySource(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	if err = receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	client := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
	firstSource := reserveUDPSource(t)
	secondSource := reserveUDPSource(t)
	for secondSource == firstSource {
		secondSource = reserveUDPSource(t)
	}

	key := udpSessionKey{Source: client, Scope: udpSessionScopeLocalTC}
	inbound := &Inbound{}
	inbound.udpClientTable.setDirectBinding(key, firstSource, nil, 0)
	state, loaded := inbound.udpClientTable.load(key)
	if !loaded {
		t.Fatal("UDP client state is missing")
	}
	created := make(map[netip.AddrPort]int)
	writer := &tcPacketWriter{
		inbound:     inbound,
		key:         key,
		clientState: state,
		newReplySocket: func(source netip.AddrPort) (*net.UDPConn, error) {
			created[source]++
			return net.ListenUDP("udp4", net.UDPAddrFromAddrPort(source))
		},
	}
	if _, loaded = any(writer).(N.PacketBatchWriter); !loaded {
		t.Fatal("TC packet writer does not advertise batch writes")
	}
	buffers := []*buf.Buffer{
		buf.As([]byte("first-a")).ToOwned(),
		buf.As([]byte("second")).ToOwned(),
		buf.As([]byte("first-b")).ToOwned(),
	}
	if err = writer.WritePacketBatch(buffers, []M.Socksaddr{
		M.SocksaddrFromNetIP(firstSource),
		M.SocksaddrFromNetIP(secondSource),
		M.SocksaddrFromNetIP(firstSource),
	}); err != nil {
		t.Fatal(err)
	}
	defer inbound.udpReplySockets.close()
	if created[firstSource] != 1 || created[secondSource] != 1 {
		t.Fatalf("reply sockets were not reused per source: %v", created)
	}

	received := make(map[string]netip.AddrPort)
	packet := make([]byte, 64)
	for range 3 {
		n, source, readErr := receiver.ReadFromUDPAddrPort(packet)
		if readErr != nil {
			t.Fatal(readErr)
		}
		received[string(packet[:n])] = source
	}
	if received["first-a"] != firstSource || received["first-b"] != firstSource || received["second"] != secondSource {
		t.Fatalf("unexpected batch reply sources: %v", received)
	}
}

func reserveUDPSource(t *testing.T) netip.AddrPort {
	t.Helper()
	connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	address := connection.LocalAddr().(*net.UDPAddr).AddrPort()
	if err = connection.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}
