//go:build with_ebpf && (linux || android) && ebpf_integration

package ebpf

import (
	"errors"
	"runtime"
	"testing"
	"unsafe"

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
			attribute := mapCreateAttr{
				MapType:    1,
				KeySize:    uint32(unsafe.Sizeof(uint32(0))),
				ValueSize:  uint32(unsafe.Sizeof(uint64(0))),
				MaxEntries: 8,
			}
			fd, _, errno := unix.Syscall(
				unix.SYS_BPF,
				bpfMapCreate,
				uintptr(unsafe.Pointer(&attribute)),
				unsafe.Sizeof(attribute),
			)
			if errno != 0 {
				t.Fatal(errno)
			}
			mapFD := int(fd)
			t.Cleanup(func() { _ = unix.Close(mapFD) })

			keys := []uint32{1, 2, 3, 4}
			values := []uint64{10, 20, 30, 40}
			var updateSupport mapBatchSupport
			var deleteSupport mapBatchSupport
			if test.forceFallback {
				updateSupport.mode.Store(mapBatchUnsupported)
				deleteSupport.mode.Store(mapBatchUnsupported)
			}
			processed, err := updateMapBatch(
				mapFD,
				unsafe.Pointer(&keys[0]),
				unsafe.Pointer(&values[0]),
				uint32(len(keys)),
				unsafe.Sizeof(keys[0]),
				unsafe.Sizeof(values[0]),
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

			processed, err = deleteMapBatch(
				mapFD,
				unsafe.Pointer(&keys[0]),
				uint32(len(keys)),
				unsafe.Sizeof(keys[0]),
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
		})
	}
}
