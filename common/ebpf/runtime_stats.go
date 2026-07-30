//go:build with_ebpf && (linux || android) && cgo

package ebpf

import "unsafe"

const (
	statTCPRedirectEntries uint32 = iota
	statUDPRedirectEntries
	statUDPRedirectDeletes
	statTokenCollisions
	statMapUpdateFailures
	statRedirectDrops
	statCount
)

func (b *Backend) RuntimeStats() (RuntimeStats, error) {
	if b == nil {
		return RuntimeStats{}, osErrClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return RuntimeStats{}, osErrClosed
	}
	var values [statCount]uint64
	for key := uint32(0); key < statCount; key++ {
		if err := lookupMap(b.statsMap, unsafe.Pointer(&key), unsafe.Pointer(&values[key])); err != nil {
			return RuntimeStats{}, err
		}
	}
	return RuntimeStats{
		TCPRedirectEntries: subtractCounter(values[statTCPRedirectEntries], b.tcpRedirectDeletes.Load()),
		UDPRedirectEntries: subtractCounter(
			values[statUDPRedirectEntries],
			values[statUDPRedirectDeletes]+b.udpRedirectDeletes.Load(),
		),
		TokenCollisions:   values[statTokenCollisions],
		MapUpdateFailures: values[statMapUpdateFailures],
		RedirectDrops:     values[statRedirectDrops],
		LookupMisses:      b.lookupMisses.Load(),
	}, nil
}

func subtractCounter(value uint64, deleted uint64) uint64 {
	if deleted >= value {
		return 0
	}
	return value - deleted
}
