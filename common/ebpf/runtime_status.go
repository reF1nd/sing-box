//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"sort"
	"sync"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type RuntimeMapStatus struct {
	Name         string `json:"name"`
	Type         string `json:"type"`
	ID           uint32 `json:"id,omitempty"`
	KeySize      uint32 `json:"key_size"`
	ValueSize    uint32 `json:"value_size"`
	MemlockBytes uint64 `json:"memlock_bytes,omitempty"`
	Entries      uint32 `json:"entries"`
	Capacity     uint32 `json:"capacity"`
	EntriesKnown bool   `json:"entries_known"`
	Error        string `json:"error,omitempty"`
}

type RuntimeProgramStatus struct {
	Name         string `json:"name"`
	Section      string `json:"section"`
	ID           uint32 `json:"id,omitempty"`
	MemlockBytes uint64 `json:"memlock_bytes,omitempty"`
	Loaded       bool   `json:"loaded"`
	Attached     bool   `json:"attached"`
	AttachType   string `json:"attach_type,omitempty"`
	Error        string `json:"error,omitempty"`
}

type CgroupRuntimeStatus struct {
	UDPCleanupMode                 string                 `json:"udp_cleanup_mode"`
	TCPRedirectReservationFailures uint64                 `json:"tcp_redirect_reservation_failures"`
	UDPRedirectReservationFailures uint64                 `json:"udp_redirect_reservation_failures"`
	StatsError                     string                 `json:"stats_error,omitempty"`
	Maps                           []RuntimeMapStatus     `json:"maps"`
	Programs                       []RuntimeProgramStatus `json:"programs"`
}

type SharedNetworkRuntimeStatus struct {
	Maps     []RuntimeMapStatus     `json:"maps"`
	Programs []RuntimeProgramStatus `json:"programs"`
}

type runtimeStatusCollector struct {
	access       sync.Mutex
	batchSupport map[CiliumEBPF.MapType]*mapBatchSupport
}

func (c *runtimeStatusCollector) collect(maps map[string]*CiliumEBPF.Map) []RuntimeMapStatus {
	c.access.Lock()
	defer c.access.Unlock()
	if c.batchSupport == nil {
		c.batchSupport = make(map[CiliumEBPF.MapType]*mapBatchSupport)
	}
	names := make([]string, 0, len(maps))
	for name := range maps {
		names = append(names, name)
	}
	sort.Strings(names)
	status := make([]RuntimeMapStatus, 0, len(names))
	for _, name := range names {
		mapInstance := maps[name]
		entry := RuntimeMapStatus{Name: name}
		if mapInstance == nil {
			entry.Error = "map is unavailable"
			status = append(status, entry)
			continue
		}
		info, err := mapInstance.Info()
		if err != nil {
			entry.Error = err.Error()
			status = append(status, entry)
			continue
		}
		entry.Type = info.Type.String()
		entry.KeySize = info.KeySize
		entry.ValueSize = info.ValueSize
		entry.Capacity = info.MaxEntries
		if id, available := info.ID(); available {
			entry.ID = uint32(id)
		}
		if memlock, available := info.Memlock(); available {
			entry.MemlockBytes = memlock
		}
		if info.Type == CiliumEBPF.Array || info.Type == CiliumEBPF.PerCPUArray {
			entry.Entries = info.MaxEntries
			entry.EntriesKnown = true
			status = append(status, entry)
			continue
		}
		if info.Type == CiliumEBPF.Hash || info.Type == CiliumEBPF.LPMTrie {
			support := c.batchSupport[info.Type]
			if support == nil {
				support = new(mapBatchSupport)
				c.batchSupport[info.Type] = support
			}
			entry.Entries, err = countMapEntriesEfficient(
				mapInstance.FD(),
				uintptr(info.KeySize),
				uintptr(info.ValueSize),
				info.MaxEntries,
				support,
			)
		} else {
			// Reading LRU values would refresh their eviction order. Key-only
			// traversal is slower but keeps diagnostics observational.
			entry.Entries, err = countMapEntries(
				mapInstance.FD(),
				uintptr(info.KeySize),
				info.MaxEntries,
			)
		}
		if err == nil {
			entry.EntriesKnown = true
		} else {
			entry.Error = err.Error()
		}
		status = append(status, entry)
	}
	return status
}

func countMapEntriesEfficient(
	mapFD int,
	keySize uintptr,
	valueSize uintptr,
	capacity uint32,
	support *mapBatchSupport,
) (uint32, error) {
	if keySize == 0 || valueSize == 0 || capacity == 0 {
		return 0, unix.EINVAL
	}
	if support.mode.Load() != mapBatchUnsupported {
		count, err := countMapEntriesBatch(mapFD, keySize, valueSize, capacity)
		if err == nil {
			support.mode.CompareAndSwap(mapBatchUnknown, mapBatchSupported)
			return count, nil
		}
		if !mapBatchUnsupportedError(err) {
			return count, err
		}
		support.mode.Store(mapBatchUnsupported)
	}
	return countMapEntries(mapFD, keySize, capacity)
}

func countMapEntriesBatch(mapFD int, keySize uintptr, valueSize uintptr, capacity uint32) (uint32, error) {
	batchCapacity := min(uint32(mapBatchMaxEntries), capacity)
	keys := make([]byte, uintptr(batchCapacity)*keySize)
	values := make([]byte, uintptr(batchCapacity)*valueSize)
	cursor := make([]byte, keySize)
	var cursorPointer unsafe.Pointer
	var count uint32
	for count < capacity {
		batchSize := min(batchCapacity, capacity-count)
		batchCount, err := lookupMapBatch(
			mapFD,
			cursorPointer,
			unsafe.Pointer(&cursor[0]),
			unsafe.Pointer(&keys[0]),
			unsafe.Pointer(&values[0]),
			batchSize,
		)
		count += batchCount
		if errors.Is(err, unix.ENOENT) {
			return count, nil
		}
		if err != nil {
			return count, err
		}
		if batchCount == 0 {
			return count, unix.EIO
		}
		cursorPointer = unsafe.Pointer(&cursor[0])
	}
	return count, nil
}

func runtimeProgramStatus(program *CiliumEBPF.Program, name string, section string) RuntimeProgramStatus {
	status := RuntimeProgramStatus{Name: name, Section: section, Loaded: program != nil}
	if program == nil {
		return status
	}
	info, err := program.Info()
	if err != nil {
		status.Error = err.Error()
		return status
	}
	if id, available := info.ID(); available {
		status.ID = uint32(id)
	}
	if memlock, available := info.Memlock(); available {
		status.MemlockBytes = memlock
	}
	return status
}
