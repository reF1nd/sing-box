//go:build with_ebpf && ebpf_debug && (linux || android)

package ebpf

import (
	"errors"
	"io"
	"sort"
	"sync"
	"sync/atomic"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

type DebugMapStatus struct {
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

type DebugProgramStatus struct {
	Name            string `json:"name"`
	ID              uint32 `json:"id,omitempty"`
	MemlockBytes    uint64 `json:"memlock_bytes,omitempty"`
	RunCount        uint64 `json:"run_count,omitempty"`
	RuntimeNanos    uint64 `json:"runtime_ns,omitempty"`
	AverageNanos    uint64 `json:"average_ns_per_run,omitempty"`
	RecursionMisses uint64 `json:"recursion_misses,omitempty"`
	StatsKnown      bool   `json:"stats_known"`
	Error           string `json:"error,omitempty"`
}

type DebugRuntimeStatus struct {
	Maps     []DebugMapStatus     `json:"maps"`
	Programs []DebugProgramStatus `json:"programs"`
}

var programRuntimeStatsState struct {
	access sync.Mutex
	closer io.Closer
	users  uint64
}

func AcquireProgramRuntimeStats() (func() error, error) {
	programRuntimeStatsState.access.Lock()
	defer programRuntimeStatsState.access.Unlock()
	if programRuntimeStatsState.users == 0 {
		closer, err := CiliumEBPF.EnableStats(uint32(unix.BPF_STATS_RUN_TIME))
		if err != nil {
			return nil, err
		}
		programRuntimeStatsState.closer = closer
	}
	programRuntimeStatsState.users++
	var released atomic.Bool
	return func() error {
		if !released.CompareAndSwap(false, true) {
			return nil
		}
		programRuntimeStatsState.access.Lock()
		defer programRuntimeStatsState.access.Unlock()
		if programRuntimeStatsState.users == 0 {
			return nil
		}
		programRuntimeStatsState.users--
		if programRuntimeStatsState.users != 0 {
			return nil
		}
		closer := programRuntimeStatsState.closer
		programRuntimeStatsState.closer = nil
		if closer == nil {
			return nil
		}
		return closer.Close()
	}, nil
}

func (b *CgroupBackend) DebugRuntimeStatus() DebugRuntimeStatus {
	if b == nil {
		return DebugRuntimeStatus{}
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return DebugRuntimeStatus{}
	}
	return collectDebugRuntimeStatus(b.runtime.maps, b.runtime.programs)
}

func (b *SharedNetworkBackend) DebugRuntimeStatus() DebugRuntimeStatus {
	if b == nil {
		return DebugRuntimeStatus{}
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return DebugRuntimeStatus{}
	}
	return collectDebugRuntimeStatus(b.runtime.maps, b.runtime.programs)
}

func collectDebugRuntimeStatus(
	maps map[string]*CiliumEBPF.Map,
	programs []*CiliumEBPF.Program,
) DebugRuntimeStatus {
	status := DebugRuntimeStatus{
		Maps:     make([]DebugMapStatus, 0, len(maps)),
		Programs: make([]DebugProgramStatus, 0, len(programs)),
	}
	names := make([]string, 0, len(maps))
	for name := range maps {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		status.Maps = append(status.Maps, debugMapStatus(name, maps[name]))
	}
	for _, program := range programs {
		status.Programs = append(status.Programs, debugProgramStatus(program))
	}
	return status
}

func debugMapStatus(name string, mapInstance *CiliumEBPF.Map) DebugMapStatus {
	status := DebugMapStatus{Name: name}
	if mapInstance == nil {
		status.Error = "map is unavailable"
		return status
	}
	info, err := mapInstance.Info()
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.Type = info.Type.String()
	status.KeySize = info.KeySize
	status.ValueSize = info.ValueSize
	status.Capacity = info.MaxEntries
	if id, available := info.ID(); available {
		status.ID = uint32(id)
	}
	if memlock, available := info.Memlock(); available {
		status.MemlockBytes = memlock
	}
	if info.Type == CiliumEBPF.Array || info.Type == CiliumEBPF.PerCPUArray {
		status.Entries = info.MaxEntries
		status.EntriesKnown = true
		return status
	}
	status.Entries, err = countMapEntries(mapInstance.FD(), uintptr(info.KeySize), info.MaxEntries)
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.EntriesKnown = true
	return status
}

func countMapEntries(mapFD int, keySize uintptr, capacity uint32) (uint32, error) {
	if keySize == 0 || capacity == 0 {
		return 0, unix.EINVAL
	}
	current := make([]byte, keySize)
	next := make([]byte, keySize)
	seen := make(map[string]struct{})
	var currentPointer unsafe.Pointer
	for uint32(len(seen)) <= capacity {
		err := mapOperation(
			bpfMapGetNextKey,
			mapFD,
			currentPointer,
			unsafe.Pointer(&next[0]),
			0,
		)
		if errors.Is(err, unix.ENOENT) {
			return uint32(len(seen)), nil
		}
		if err != nil {
			return 0, err
		}
		encoded := string(next)
		if _, loaded := seen[encoded]; loaded {
			return uint32(len(seen)), nil
		}
		seen[encoded] = struct{}{}
		copy(current, next)
		currentPointer = unsafe.Pointer(&current[0])
	}
	return uint32(len(seen)), nil
}

func debugProgramStatus(program *CiliumEBPF.Program) DebugProgramStatus {
	if program == nil {
		return DebugProgramStatus{Error: "program is unavailable"}
	}
	status := DebugProgramStatus{}
	info, err := program.Info()
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.Name = info.Name
	if id, available := info.ID(); available {
		status.ID = uint32(id)
	}
	if memlock, available := info.Memlock(); available {
		status.MemlockBytes = memlock
	}
	stats, err := program.Stats()
	if err != nil {
		status.Error = err.Error()
		return status
	}
	status.StatsKnown = true
	status.RunCount = stats.RunCount
	status.RuntimeNanos = uint64(max(stats.Runtime.Nanoseconds(), 0))
	status.RecursionMisses = stats.RecursionMisses
	if stats.RunCount != 0 {
		status.AverageNanos = status.RuntimeNanos / stats.RunCount
	}
	return status
}
