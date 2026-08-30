//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"sync"

	CiliumEBPF "github.com/cilium/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

// Linux 6.6.0 through 6.6.46 may report an UBSAN out-of-bounds access when
// an LPM trie key is updated. The upstream fix adds this BTF type name.
const lpmTrieFlexibleKeyFix = "bpf_lpm_trie_key_u8"

var (
	lpmTrieSafetyOnce sync.Once
	lpmTrieSafety     lpmTrieKernelSafety
	lpmTrieProbeOnce  sync.Once
	lpmTrieProbeErr   error
)

type lpmTrieKernelSafety struct {
	release string
	unsafe  bool
}

func checkLPMTriePolicyCompatibility(scope string, entries int) error {
	if entries == 0 {
		return nil
	}
	lpmTrieSafetyOnce.Do(func() { lpmTrieSafety = detectLPMTrieKernelSafety() })
	if lpmTrieSafety.unsafe {
		return E.New(
			"refusing to update ", scope, " LPM trie on kernel ", lpmTrieSafety.release,
			": this release may panic under the Linux LPM trie UBSAN defect; update to 6.6.47 or a kernel containing ",
			lpmTrieFlexibleKeyFix,
		)
	}
	lpmTrieProbeOnce.Do(func() { lpmTrieProbeErr = probeLPMTrieUpdate() })
	if lpmTrieProbeErr != nil {
		return E.Cause(lpmTrieProbeErr, "probe ", scope, " LPM trie update")
	}
	return nil
}

func probeLPMTrieUpdate() error {
	mapInstance, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Name: "sb_lpm_probe", Type: CiliumEBPF.LPMTrie, KeySize: 8, ValueSize: 1, MaxEntries: 1, Flags: 1,
	})
	if err != nil {
		return err
	}
	defer mapInstance.Close()
	key := struct {
		PrefixLength uint32
		Address      [4]byte
	}{PrefixLength: 32, Address: [4]byte{192, 0, 2, 1}}
	value := uint8(1)
	return mapInstance.Update(&key, &value, CiliumEBPF.UpdateAny)
}

func detectLPMTrieKernelSafety() lpmTrieKernelSafety {
	releaseBytes, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return lpmTrieKernelSafety{}
	}
	release := strings.TrimSpace(string(releaseBytes))
	safety := lpmTrieKernelSafety{release: release}
	if !knownUnsafeLPMTrieRelease(release) {
		return safety
	}
	// BTF is a positive signal for the upstream flexible-key fix. If BTF is
	// unavailable on a kernel in the affected range, fail closed before any
	// LPM update can reach the vulnerable code.
	btfData, btfErr := os.ReadFile("/sys/kernel/btf/vmlinux")
	if btfErr != nil || !bytes.Contains(btfData, []byte(lpmTrieFlexibleKeyFix)) {
		safety.unsafe = true
	}
	return safety
}

func knownUnsafeLPMTrieRelease(release string) bool {
	version := strings.SplitN(release, "-", 2)[0]
	parts := strings.Split(version, ".")
	if len(parts) < 3 {
		return false
	}
	major, majorLoaded := leadingVersionNumber(parts[0])
	minor, minorLoaded := leadingVersionNumber(parts[1])
	patch, patchLoaded := leadingVersionNumber(parts[2])
	return majorLoaded && minorLoaded && patchLoaded && major == 6 && minor == 6 && patch < 47
}

func leadingVersionNumber(value string) (int, bool) {
	end := 0
	for end < len(value) && value[end] >= '0' && value[end] <= '9' {
		end++
	}
	if end == 0 {
		return 0, false
	}
	number, err := strconv.Atoi(value[:end])
	return number, err == nil
}
