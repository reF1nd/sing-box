//go:build with_ebpf && (linux || android)

package ebpf

import (
	"path/filepath"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
)

func TestBPFObjectsFitLinux419Verifier(t *testing.T) {
	const (
		legacyInstructionLimit    = 4096
		legacyInstructionHeadroom = 128
		legacyInstructionBudget   = legacyInstructionLimit - legacyInstructionHeadroom
	)
	objects := []struct {
		name string
		file string
	}{
		{"cgroup/bpfel", "cgroup_bpfel.o"},
		{"cgroup/bpfeb", "cgroup_bpfeb.o"},
		{"shared-network/bpfel", "shared_network_bpfel.o"},
		{"shared-network/bpfeb", "shared_network_bpfeb.o"},
	}
	for _, object := range objects {
		var maxProgram string
		var maxInstructions uint64
		spec, err := CiliumEBPF.LoadCollectionSpec(filepath.Join("internal", "bpfgen", object.file))
		if err != nil {
			t.Fatalf("load %s object: %v", object.name, err)
		}
		for programName, program := range spec.Programs {
			rawInstructionCount := program.Instructions.Size() / 8
			if rawInstructionCount > maxInstructions {
				maxProgram = programName
				maxInstructions = rawInstructionCount
			}
			if rawInstructionCount > legacyInstructionLimit {
				t.Errorf("%s/%s has %d raw instructions; Linux 4.19 permits at most %d",
					object.name, programName, rawInstructionCount, legacyInstructionLimit)
			} else if rawInstructionCount > legacyInstructionBudget {
				t.Errorf("%s/%s has %d raw instructions; keep at least %d instructions below the Linux 4.19 limit",
					object.name, programName, rawInstructionCount, legacyInstructionHeadroom)
			}
			symbols, err := program.Instructions.SymbolOffsets()
			if err != nil {
				t.Errorf("resolve %s/%s symbols: %v", object.name, programName, err)
				continue
			}
			iterator := program.Instructions.Iterate()
			for iterator.Next() {
				if !iterator.Ins.OpCode.Class().IsJump() || iterator.Ins.IsFunctionCall() {
					continue
				}
				if reference := iterator.Ins.Reference(); reference != "" {
					target, loaded := symbols[reference]
					if !loaded {
						t.Errorf("%s/%s references missing symbol %s", object.name, programName, reference)
						continue
					}
					if target > iterator.Index {
						continue
					}
				} else if iterator.Ins.Offset >= 0 {
					continue
				}
				t.Errorf("%s/%s has a backward jump at raw instruction %d; Linux 4.19 has no bounded-loop verifier support",
					object.name, programName, iterator.Offset)
			}
		}
		t.Logf("%s maximum: %s with %d raw instructions", object.name, maxProgram, maxInstructions)
	}
}
