//go:build with_ebpf && (linux || android) && ebpf_integration

package ebpf

import (
	"errors"
	"runtime"
	"testing"
	"unsafe"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func TestMapBatchIntegration(t *testing.T) {
	requireEBPFIntegration(t, "test BPF map batch operations")
	for _, test := range []struct {
		name          string
		forceFallback bool
	}{
		{name: "kernel"},
		{name: "fallback", forceFallback: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			const maxEntries = 8
			mapInstance, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
				Type:       CiliumEBPF.Hash,
				KeySize:    uint32(unsafe.Sizeof(uint32(0))),
				ValueSize:  uint32(unsafe.Sizeof(uint64(0))),
				MaxEntries: maxEntries,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = mapInstance.Close() })
			mapFD := mapInstance.FD()

			keys := []uint32{1, 2, 3, 4}
			values := []uint64{10, 20, 30, 40}
			var updateSupport mapBatchSupport
			var deleteSupport mapBatchSupport
			if test.forceFallback {
				updateSupport.mode.Store(mapBatchUnsupported)
				deleteSupport.mode.Store(mapBatchUnsupported)
			}
			processed, err := updateMapBatch(
				mapInstance,
				keys,
				values,
				0,
				&updateSupport,
			)
			runtime.KeepAlive(keys)
			runtime.KeepAlive(values)
			if err != nil || processed != uint32(len(keys)) {
				t.Fatalf("batch update: processed=%d err=%v", processed, err)
			}
			for index, key := range keys {
				var value uint64
				if err = lookupMap(mapFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
					t.Fatal(err)
				}
				if value != values[index] {
					t.Fatalf("unexpected value for key %d: %d", key, value)
				}
			}
			entries, err := countMapEntriesForTest(mapFD, unsafe.Sizeof(keys[0]), maxEntries)
			if err != nil {
				t.Fatal(err)
			}
			if entries != uint32(len(keys)) {
				t.Fatalf("unexpected map entry count: %d", entries)
			}
			var scanScratch mapScanScratch[uint32, uint64]
			if test.forceFallback {
				scanScratch.lookupSupport.mode.Store(mapBatchUnsupported)
			}
			scannedValues := make(map[uint32]uint64)
			var scan mapScanResult
			for !scan.Complete {
				scan, err = scanScratch.scan(
					mapInstance,
					maxEntries,
					2,
					func(key uint32, value uint64) {
						scannedValues[key] = value
					},
				)
				if err != nil {
					t.Fatal(err)
				}
				if test.forceFallback && scan.Scanned > 2 {
					t.Fatalf("fallback scan exceeded budget: %d", scan.Scanned)
				}
			}
			if scan.Entries != uint32(len(keys)) {
				t.Fatalf("unexpected scanned map entry count: %d", scan.Entries)
			}
			for index, key := range keys {
				if value := scannedValues[key]; value != values[index] {
					t.Fatalf("unexpected scanned value for key %d: %d", key, value)
				}
			}

			processed, err = deleteMapBatch(
				mapInstance,
				keys,
				&deleteSupport,
			)
			runtime.KeepAlive(keys)
			if err != nil || processed != uint32(len(keys)) {
				t.Fatalf("batch delete: processed=%d err=%v", processed, err)
			}
			for _, key := range keys {
				var value uint64
				if err = lookupMap(mapFD, unsafe.Pointer(&key), unsafe.Pointer(&value)); !errors.Is(err, unix.ENOENT) {
					t.Fatalf("deleted key %d remains: %v", key, err)
				}
			}
			entries, err = countMapEntriesForTest(mapFD, unsafe.Sizeof(keys[0]), maxEntries)
			if err != nil {
				t.Fatal(err)
			}
			if entries != 0 {
				t.Fatalf("unexpected map entry count after delete: %d", entries)
			}
			processed, err = deleteMapBatchIfExists(mapInstance, keys, &deleteSupport)
			if err != nil || processed != 0 {
				t.Fatalf("delete missing keys: processed=%d err=%v", processed, err)
			}
		})
	}
}

func TestLRUFallbackBoundedIntegration(t *testing.T) {
	requireEBPFIntegration(t, "test bounded LRU fallback")
	const maxEntries = 8
	mapInstance, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.LRUHash,
		KeySize:    uint32(unsafe.Sizeof(uint64(0))),
		ValueSize:  uint32(unsafe.Sizeof(uint64(0))),
		MaxEntries: maxEntries,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = mapInstance.Close() })
	for key := uint64(0); key < 256; key++ {
		value := key + 1
		if err = updateMap(mapInstance.FD(), unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
			t.Fatalf("update LRU fallback at key %d: %v", key, err)
		}
	}
	entries, err := countMapEntriesForTest(mapInstance.FD(), unsafe.Sizeof(uint64(0)), maxEntries)
	if err != nil {
		t.Fatal(err)
	}
	if entries != maxEntries {
		t.Fatalf("unexpected bounded LRU entry count: %d", entries)
	}
}

func BenchmarkMapScanMaintenance(b *testing.B) {
	requireEBPFIntegration(b, "benchmark BPF map maintenance scans")
	const maxEntries = 65536
	mapInstance, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.Hash,
		KeySize:    uint32(unsafe.Sizeof(uint32(0))),
		ValueSize:  uint32(unsafe.Sizeof(uint64(0))),
		MaxEntries: maxEntries,
		Flags:      bpfFlagNoPrealloc,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = mapInstance.Close() })
	keys := make([]uint32, maxEntries)
	values := make([]uint64, maxEntries)
	for index := range keys {
		keys[index] = uint32(index)
		values[index] = uint64(index)
	}
	var updateSupport mapBatchSupport
	if _, err = updateMapBatch(
		mapInstance,
		keys,
		values,
		0,
		&updateSupport,
	); err != nil {
		b.Fatal(err)
	}
	runtime.KeepAlive(keys)
	runtime.KeepAlive(values)

	for _, testCase := range []struct {
		name          string
		forceFallback bool
	}{
		{name: "batch-full"},
		{name: "fallback-chunk", forceFallback: true},
	} {
		b.Run(testCase.name, func(b *testing.B) {
			var scratch mapScanScratch[uint32, uint64]
			if testCase.forceFallback {
				scratch.lookupSupport.mode.Store(mapBatchUnsupported)
			}
			var scanned uint64
			var visited uint64
			b.ResetTimer()
			for range b.N {
				result, scanErr := scratch.scan(
					mapInstance,
					maxEntries,
					mapBatchMaxEntries,
					func(_ uint32, value uint64) {
						visited += value & 1
					},
				)
				if scanErr != nil {
					b.Fatal(scanErr)
				}
				scanned += uint64(result.Scanned)
			}
			b.StopTimer()
			b.ReportMetric(float64(scanned)/float64(b.N), "entries/op")
			runtime.KeepAlive(visited)
		})
	}
}

func BenchmarkConnectedUDPTokenRecoveryScan(b *testing.B) {
	requireEBPFIntegration(b, "benchmark connected UDP token recovery scans")
	const maxEntries = UDPRedirectMapCapacity
	mapInstance, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Type:       CiliumEBPF.LRUHash,
		KeySize:    uint32(unsafe.Sizeof(uint64(0))),
		ValueSize:  uint32(unsafe.Sizeof(listenerLookupKey{})),
		MaxEntries: maxEntries,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = mapInstance.Close() })
	keys := make([]uint64, maxEntries)
	values := make([]listenerLookupKey, maxEntries)
	for index := range keys {
		keys[index] = uint64(index + 1)
		values[index] = listenerLookupKey{
			Family:       addressFamilyIPv4,
			Protocol:     ProtocolUDP,
			ListenerPort: uint16(index),
		}
	}
	var updateSupport mapBatchSupport
	if _, err = updateMapBatch(mapInstance, keys, values, 0, &updateSupport); err != nil {
		b.Fatal(err)
	}
	runtime.KeepAlive(keys)
	runtime.KeepAlive(values)
	missing := listenerLookupKey{Family: addressFamilyIPv6, Protocol: ProtocolUDP}

	for _, testCase := range []struct {
		name          string
		forceFallback bool
	}{
		{name: "batch-full-miss"},
		{name: "fallback-full-miss", forceFallback: true},
	} {
		b.Run(testCase.name, func(b *testing.B) {
			backend := &CgroupBackend{mapCapacity: CgroupMapCapacity{UDPRedirect: maxEntries}}
			if testCase.forceFallback {
				backend.connectedUDPTokenLookupSupport.mode.Store(mapBatchUnsupported)
			}
			b.ReportMetric(maxEntries, "entries/op")
			b.ResetTimer()
			for range b.N {
				cookie, lookupErr := backend.findConnectedUDPToken(mapInstance, missing)
				if cookie != 0 || !errors.Is(lookupErr, unix.ENOENT) {
					b.Fatalf("unexpected lookup result: cookie=%d err=%v", cookie, lookupErr)
				}
			}
		})
	}
}
