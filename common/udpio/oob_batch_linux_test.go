//go:build linux

package udpio

import (
	"net"
	"net/netip"
	"testing"
	"time"
	"unsafe"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"golang.org/x/sys/unix"
)

func TestMMsgHdrABI(t *testing.T) {
	var header mmsghdr
	messageHeaderSize := unsafe.Sizeof(header.msgHdr)
	if offset := unsafe.Offsetof(header.msgLen); offset != messageHeaderSize {
		t.Fatalf("mmsghdr.msgLen offset=%d, want %d", offset, messageHeaderSize)
	}
	alignment := unsafe.Alignof(header.msgHdr)
	expectedSize := messageHeaderSize + unsafe.Sizeof(header.msgLen)
	expectedSize = (expectedSize + alignment - 1) &^ (alignment - 1)
	if size := unsafe.Sizeof(header); size != expectedSize {
		t.Fatalf("mmsghdr size=%d, want %d", size, expectedSize)
	}
}

func TestOOBPacketBatchReadWriteIPv4(t *testing.T) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	if err = enableIPv4PacketInfo(receiver); err != nil {
		t.Fatal(err)
	}
	if err = receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	reader, created := NewOOBPacketBatchReadWaiter(receiver, 256)
	if !created {
		t.Fatal("OOB packet batch reader was not created")
	}
	reader.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8})

	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	writer, created := NewOOBPacketBatchWriter(sender, false)
	if !created {
		t.Fatal("OOB packet batch writer was not created")
	}
	sourceAddresses := []netip.Addr{
		netip.MustParseAddr("127.0.0.2"),
		netip.MustParseAddr("127.0.0.3"),
		netip.MustParseAddr("127.0.0.4"),
	}
	writeBuffers := make([]*buf.Buffer, len(sourceAddresses))
	oobs := make([][]byte, len(sourceAddresses))
	destinations := make([]M.Socksaddr, len(sourceAddresses))
	for index, source := range sourceAddresses {
		writeBuffers[index] = buf.As([]byte{byte(index + 1)}).ToOwned()
		oobs[index] = marshalIPv4PacketInfo(source)
		destinations[index] = M.SocksaddrFromNet(receiver.LocalAddr())
	}
	if err = writer.WriteOOBPacketBatch(writeBuffers, oobs, destinations); err != nil {
		t.Fatal(err)
	}

	readBuffers, readOOBs, sources, err := reader.WaitReadOOBPackets()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(readBuffers)
	if len(readBuffers) != len(sourceAddresses) || len(readOOBs) != len(sourceAddresses) || len(sources) != len(sourceAddresses) {
		t.Fatalf("unexpected batch sizes: buffers=%d oobs=%d sources=%d", len(readBuffers), len(readOOBs), len(sources))
	}
	for index, buffer := range readBuffers {
		payloadIndex := int(buffer.Byte(0)) - 1
		if payloadIndex < 0 || payloadIndex >= len(sourceAddresses) {
			t.Fatalf("unexpected payload: %v", buffer.Bytes())
		}
		if sources[index].Addr != sourceAddresses[payloadIndex] {
			t.Fatalf("payload %d has source %v, want %v", payloadIndex, sources[index], sourceAddresses[payloadIndex])
		}
		if !containsPacketInfo(readOOBs[index], unix.IPPROTO_IP, unix.IP_PKTINFO) {
			t.Fatalf("payload %d is missing IP_PKTINFO: %v", payloadIndex, readOOBs[index])
		}
	}
}

func TestOOBPacketBatchReadWriteIPv6(t *testing.T) {
	receiver, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6loopback})
	if err != nil {
		t.Skipf("IPv6 loopback is unavailable: %v", err)
	}
	defer receiver.Close()
	if err = enableIPv6PacketInfo(receiver); err != nil {
		t.Fatal(err)
	}
	if err = receiver.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	reader, created := NewOOBPacketBatchReadWaiter(receiver, 256)
	if !created {
		t.Fatal("IPv6 OOB packet batch reader was not created")
	}
	reader.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8})

	sender, err := net.ListenUDP("udp6", &net.UDPAddr{IP: net.IPv6unspecified})
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	writer, created := NewOOBPacketBatchWriter(sender, true)
	if !created {
		t.Fatal("IPv6 OOB packet batch writer was not created")
	}
	source := netip.IPv6Loopback()
	writeBuffers := []*buf.Buffer{
		buf.As([]byte("first")).ToOwned(),
		buf.As([]byte("second")).ToOwned(),
	}
	packetInfo := marshalIPv6PacketInfo(source)
	destination := M.SocksaddrFromNet(receiver.LocalAddr())
	if err = writer.WriteOOBPacketBatch(
		writeBuffers,
		[][]byte{packetInfo, packetInfo},
		[]M.Socksaddr{destination, destination},
	); err != nil {
		t.Fatal(err)
	}
	readBuffers, readOOBs, sources, err := reader.WaitReadOOBPackets()
	if err != nil {
		t.Fatal(err)
	}
	defer buf.ReleaseMulti(readBuffers)
	if len(readBuffers) != 2 || len(readOOBs) != 2 || len(sources) != 2 {
		t.Fatalf("unexpected IPv6 batch sizes: %d/%d/%d", len(readBuffers), len(readOOBs), len(sources))
	}
	for index := range readBuffers {
		if sources[index].Addr != source || !containsPacketInfo(readOOBs[index], unix.IPPROTO_IPV6, unix.IPV6_PKTINFO) {
			t.Fatalf("unexpected IPv6 message %d: source=%v oob=%v", index, sources[index], readOOBs[index])
		}
	}
}

func enableIPv4PacketInfo(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var socketErr error
	if err = rawConn.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_PKTINFO, 1)
	}); err != nil {
		return err
	}
	return socketErr
}

func enableIPv6PacketInfo(conn *net.UDPConn) error {
	rawConn, err := conn.SyscallConn()
	if err != nil {
		return err
	}
	var socketErr error
	if err = rawConn.Control(func(fd uintptr) {
		socketErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IPV6, unix.IPV6_RECVPKTINFO, 1)
	}); err != nil {
		return err
	}
	return socketErr
}

func marshalIPv4PacketInfo(source netip.Addr) []byte {
	oob := make([]byte, unix.CmsgSpace(unix.SizeofInet4Pktinfo))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.IPPROTO_IP
	header.Type = unix.IP_PKTINFO
	header.SetLen(unix.CmsgLen(unix.SizeofInet4Pktinfo))
	info := (*unix.Inet4Pktinfo)(unsafe.Pointer(&oob[unix.CmsgLen(0)]))
	info.Spec_dst = source.As4()
	return oob
}

func marshalIPv6PacketInfo(source netip.Addr) []byte {
	oob := make([]byte, unix.CmsgSpace(unix.SizeofInet6Pktinfo))
	header := (*unix.Cmsghdr)(unsafe.Pointer(&oob[0]))
	header.Level = unix.IPPROTO_IPV6
	header.Type = unix.IPV6_PKTINFO
	header.SetLen(unix.CmsgLen(unix.SizeofInet6Pktinfo))
	info := (*unix.Inet6Pktinfo)(unsafe.Pointer(&oob[unix.CmsgLen(0)]))
	info.Addr = source.As16()
	return oob
}

func containsPacketInfo(oob []byte, level int, messageType int) bool {
	messages, err := unix.ParseSocketControlMessage(oob)
	if err != nil {
		return false
	}
	for _, message := range messages {
		if int(message.Header.Level) == level && int(message.Header.Type) == messageType {
			return true
		}
	}
	return false
}
