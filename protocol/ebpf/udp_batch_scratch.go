//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"sync"

	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
)

const udpBatchScratchRetainLimit = 256

// udpBatchMetadataScratch holds the parallel metadata slices required by the
// listener batch API. Writers may be called concurrently, so package pools are
// used instead of mutable writer-owned state.
type udpBatchMetadataScratch struct {
	packetInfos [][]byte
	sources     []netip.Addr
}

var udpBatchMetadataPool = sync.Pool{
	New: func() any { return new(udpBatchMetadataScratch) },
}

type udpListenerBatchGroup struct {
	buffers      []*buf.Buffer
	packetInfos  [][]byte
	destinations []M.Socksaddr
}

type udpListenerBatchScratch struct {
	ipv4 udpListenerBatchGroup
	ipv6 udpListenerBatchGroup
}

var udpListenerBatchPool = sync.Pool{
	New: func() any { return new(udpListenerBatchScratch) },
}

func acquireUDPListenerBatch() *udpListenerBatchScratch {
	return udpListenerBatchPool.Get().(*udpListenerBatchScratch)
}

func releaseUDPListenerBatch(scratch *udpListenerBatchScratch) {
	if scratch == nil {
		return
	}
	for _, group := range []*udpListenerBatchGroup{&scratch.ipv4, &scratch.ipv6} {
		clear(group.buffers)
		clear(group.packetInfos)
		clear(group.destinations)
		if cap(group.buffers) > udpBatchScratchRetainLimit {
			group.buffers = nil
		} else {
			group.buffers = group.buffers[:0]
		}
		if cap(group.packetInfos) > udpBatchScratchRetainLimit {
			group.packetInfos = nil
		} else {
			group.packetInfos = group.packetInfos[:0]
		}
		if cap(group.destinations) > udpBatchScratchRetainLimit {
			group.destinations = nil
		} else {
			group.destinations = group.destinations[:0]
		}
	}
	udpListenerBatchPool.Put(scratch)
}

func acquireUDPBatchMetadata(length int) *udpBatchMetadataScratch {
	scratch := udpBatchMetadataPool.Get().(*udpBatchMetadataScratch)
	if cap(scratch.packetInfos) < length {
		scratch.packetInfos = make([][]byte, length)
	} else {
		scratch.packetInfos = scratch.packetInfos[:length]
	}
	if cap(scratch.sources) < length {
		scratch.sources = make([]netip.Addr, length)
	} else {
		scratch.sources = scratch.sources[:length]
	}
	return scratch
}

func releaseUDPBatchMetadata(scratch *udpBatchMetadataScratch) {
	if scratch == nil {
		return
	}
	clear(scratch.packetInfos)
	clear(scratch.sources)
	if cap(scratch.packetInfos) > udpBatchScratchRetainLimit {
		scratch.packetInfos = nil
	} else {
		scratch.packetInfos = scratch.packetInfos[:0]
	}
	if cap(scratch.sources) > udpBatchScratchRetainLimit {
		scratch.sources = nil
	} else {
		scratch.sources = scratch.sources[:0]
	}
	udpBatchMetadataPool.Put(scratch)
}

type udpPacketGroup struct {
	source       netip.AddrPort
	buffers      []*buf.Buffer
	destinations []M.Socksaddr
}

type udpPacketGroupScratch struct {
	indices map[netip.AddrPort]int
	groups  []udpPacketGroup
}

var udpPacketGroupPool = sync.Pool{
	New: func() any {
		return &udpPacketGroupScratch{indices: make(map[netip.AddrPort]int)}
	},
}

func acquireUDPPacketGroups() *udpPacketGroupScratch {
	return udpPacketGroupPool.Get().(*udpPacketGroupScratch)
}

func (s *udpPacketGroupScratch) group(source netip.AddrPort) (*udpPacketGroup, bool) {
	if index, loaded := s.indices[source]; loaded {
		return &s.groups[index], false
	}
	index := len(s.groups)
	if index < cap(s.groups) {
		s.groups = s.groups[:index+1]
	} else {
		s.groups = append(s.groups, udpPacketGroup{})
	}
	group := &s.groups[index]
	group.source = source
	s.indices[source] = index
	return group, true
}

func releaseUDPPacketGroups(scratch *udpPacketGroupScratch) {
	if scratch == nil {
		return
	}
	if len(scratch.indices) > udpBatchScratchRetainLimit {
		scratch.indices = make(map[netip.AddrPort]int)
	} else {
		clear(scratch.indices)
	}
	for index := range scratch.groups {
		group := &scratch.groups[index]
		group.source = netip.AddrPort{}
		clear(group.buffers)
		clear(group.destinations)
		if cap(group.buffers) > udpBatchScratchRetainLimit {
			group.buffers = nil
		} else {
			group.buffers = group.buffers[:0]
		}
		if cap(group.destinations) > udpBatchScratchRetainLimit {
			group.destinations = nil
		} else {
			group.destinations = group.destinations[:0]
		}
	}
	if cap(scratch.groups) > udpBatchScratchRetainLimit {
		scratch.groups = nil
	} else {
		scratch.groups = scratch.groups[:0]
	}
	udpPacketGroupPool.Put(scratch)
}
