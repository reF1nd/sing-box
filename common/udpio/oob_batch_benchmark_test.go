//go:build linux

package udpio

import (
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing/common/buf"
	N "github.com/sagernet/sing/common/network"
)

func BenchmarkOOBBatchReceive(b *testing.B) {
	receiver, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer receiver.Close()
	sender, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		b.Fatal(err)
	}
	defer sender.Close()
	reader, ok := NewOOBPacketBatchReadWaiter(receiver, 256)
	if !ok {
		b.Fatal("no batch reader")
	}
	reader.InitializeReadWaiter(N.ReadWaitOptions{BatchSize: 8})
	if err = receiver.SetReadDeadline(time.Now().Add(time.Minute)); err != nil {
		b.Fatal(err)
	}
	target := receiver.LocalAddr().(*net.UDPAddr).AddrPort()
	payload := make([]byte, 512)
	b.ReportAllocs()
	b.SetBytes(8 * int64(len(payload)))
	b.ResetTimer()
	for b.Loop() {
		for range 8 {
			if _, err := sender.WriteToUDPAddrPort(payload, target); err != nil {
				b.Fatal(err)
			}
		}
		received := 0
		for received < 8 {
			buffers, _, _, err := reader.WaitReadOOBPackets()
			if err != nil {
				b.Fatal(err)
			}
			received += len(buffers)
			buf.ReleaseMulti(buffers)
		}
	}
}
