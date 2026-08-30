//go:build with_ebpf && (linux || android)

package ebpf

import (
	"sync"

	CiliumEBPF "github.com/cilium/ebpf"
	E "github.com/sagernet/sing/common/exceptions"
)

var (
	lpmTrieProbeOnce sync.Once
	lpmTrieProbeErr  error
)

func checkLPMTriePolicyCompatibility(scope string, entries int) error {
	if entries == 0 {
		return nil
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
