//go:build with_ebpf && (linux || android)

package ebpf

import (
	"bytes"
	"os"
	"strconv"
	"strings"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
)

const lpmTrieFlexibleKeyFix = "896880ff30866f386ebed14ab81ce1ad3710cfc4"

var (
	lpmTrieSafetyOnce sync.Once
	lpmTrieSafety     lpmTrieKernelSafety
)

type lpmTrieKernelSafety struct {
	release string
	unsafe  bool
}

func checkLPMTriePolicyCompatibility(scope string, entries int) error {
	if entries == 0 {
		return nil
	}
	lpmTrieSafetyOnce.Do(func() {
		lpmTrieSafety = detectLPMTrieKernelSafety()
	})
	if !lpmTrieSafety.unsafe {
		return nil
	}
	return E.New(
		"refusing to populate ", scope, " LPM trie policy on kernel ", lpmTrieSafety.release,
		": Linux 6.6.0-6.6.46 can panic under UBSAN; update to 6.6.47+ or a kernel containing ",
		lpmTrieFlexibleKeyFix,
	)
}

func detectLPMTrieKernelSafety() lpmTrieKernelSafety {
	releaseBytes, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return lpmTrieKernelSafety{}
	}
	release := strings.TrimSpace(string(releaseBytes))
	if !knownUnsafeLPMTrieRelease(release) {
		return lpmTrieKernelSafety{release: release}
	}
	btfData, err := os.ReadFile("/sys/kernel/btf/vmlinux")
	if err == nil && bytes.Contains(btfData, []byte("bpf_lpm_trie_key_u8")) {
		return lpmTrieKernelSafety{release: release}
	}
	return lpmTrieKernelSafety{release: release, unsafe: true}
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
