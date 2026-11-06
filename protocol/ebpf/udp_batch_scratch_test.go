//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"strconv"
	"testing"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

func BenchmarkUDPBatchMetadataScratch(b *testing.B) {
	for _, length := range []int{1, 16, 64} {
		b.Run(strconv.Itoa(length), func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				scratch := acquireUDPBatchMetadata(length)
				for index := range length {
					scratch.sources[index] = netip.IPv4Unspecified()
				}
				releaseUDPBatchMetadata(scratch)
			}
		})
	}
}

func BenchmarkUDPPacketGroupScratch(b *testing.B) {
	destinations := make([]netip.AddrPort, 64)
	for index := range destinations {
		destinations[index] = netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(10000+index%8))
	}
	client := M.SocksaddrFromNetIP(netip.MustParseAddrPort("198.51.100.1:20000"))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		scratch := acquireUDPPacketGroups()
		for _, destination := range destinations {
			group, _ := scratch.group(destination)
			group.buffers = append(group.buffers, (*buf.Buffer)(nil))
			group.destinations = append(group.destinations, client)
		}
		releaseUDPPacketGroups(scratch)
	}
}

func BenchmarkUDPListenerBatchScratch(b *testing.B) {
	client := M.SocksaddrFromNetIP(netip.MustParseAddrPort("198.51.100.1:20000"))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		scratch := acquireUDPListenerBatch()
		for index := range 64 {
			group := &scratch.ipv4
			if index&1 != 0 {
				group = &scratch.ipv6
			}
			group.buffers = append(group.buffers, (*buf.Buffer)(nil))
			group.packetInfos = append(group.packetInfos, nil)
			group.destinations = append(group.destinations, client)
		}
		releaseUDPListenerBatch(scratch)
	}
}
