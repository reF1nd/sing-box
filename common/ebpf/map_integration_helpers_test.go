//go:build with_ebpf && linux && ebpf_integration

package ebpf

import (
	"errors"

	CiliumEBPF "github.com/cilium/ebpf"
	"golang.org/x/sys/unix"
)

func countMapEntries(fd int, keySize uintptr, maxEntries uint32) (uint32, error) {
	dupFD, err := unix.Dup(fd)
	if err != nil {
		return 0, err
	}
	mapInstance, err := CiliumEBPF.NewMapFromFD(dupFD)
	if err != nil {
		return 0, err
	}
	defer mapInstance.Close()
	if keySize == 0 || keySize > uintptr(^uint(0)>>1) {
		return 0, errors.New("invalid BPF map key size")
	}
	var key []byte
	var count uint32
	for {
		next, nextErr := mapInstance.NextKeyBytes(key)
		if errors.Is(nextErr, unix.ENOENT) {
			return count, nil
		}
		if nextErr != nil {
			return 0, nextErr
		}
		if uintptr(len(next)) != keySize {
			return 0, errors.New("BPF map returned an unexpected key size")
		}
		count++
		if count > maxEntries {
			return count, nil
		}
		key = next
	}
}
