//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"fmt"
	"slices"

	BPFGen "github.com/sagernet/sing-box/common/ebpf/internal/bpfgen"
	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

const bpfFlagNoPrealloc = 1

var loadTC = BPFGen.LoadTC

var loadCgroup = BPFGen.LoadCgroup

var loadCgroupCoarse = BPFGen.LoadCgroupCoarse

var loadCgroupStorage = BPFGen.LoadCgroupStorage

var loadSharedNetwork = BPFGen.LoadSharedNetwork

func attachProgramRaw(target int, program *CiliumEBPF.Program, attachType CiliumEBPF.AttachType) error {
	if err := link.RawAttachProgram(link.RawAttachProgramOptions{Target: target, Program: program, Attach: attachType, Flags: 2}); err == nil {
		return nil
	}
	return link.RawAttachProgram(link.RawAttachProgramOptions{Target: target, Program: program, Attach: attachType})
}

func rawDetachProgram(target int, program *CiliumEBPF.Program, attachType CiliumEBPF.AttachType) error {
	return link.RawDetachProgram(link.RawDetachProgramOptions{Target: target, Program: program, Attach: attachType})
}

func sameProgramIDs(left, right []CiliumEBPF.ProgramID) bool {
	return slices.Equal(left, right)
}

func verifierErrorStage(err error) string {
	var verifierErr *CiliumEBPF.VerifierError
	if errors.As(err, &verifierErr) {
		return fmt.Sprintf("verifier rejected program: %v", verifierErr)
	}
	return ""
}

type programSelection struct {
	section string
	name    string
}

type mapSpecOverride struct {
	name       string
	mapType    CiliumEBPF.MapType
	maxEntries uint32
	flags      uint32
}

func loadObjectMaps(
	loadSpec func() (*CiliumEBPF.CollectionSpec, error),
	overrides map[string]mapSpecOverride,
) (map[string]*CiliumEBPF.Map, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, E.Cause(err, "parse eBPF object")
	}
	clear(spec.Programs)
	for name, mapSpec := range spec.Maps {
		override, selected := overrides[name]
		if !selected {
			delete(spec.Maps, name)
			continue
		}
		if override.name == "" || override.mapType == CiliumEBPF.UnspecifiedMap ||
			(override.maxEntries == 0 && override.mapType != CiliumEBPF.SkStorage) {
			return nil, E.New("invalid eBPF map override for ", name)
		}
		mapSpec.Name = override.name
		mapSpec.Type = override.mapType
		mapSpec.MaxEntries = override.maxEntries
		mapSpec.Flags = override.flags
		mapSpec.Extra = nil
	}
	for name := range overrides {
		if spec.Maps[name] == nil {
			return nil, E.New("eBPF object is missing map ", name)
		}
	}
	collection, err := CiliumEBPF.NewCollection(spec)
	if err != nil {
		return nil, eBPFOperationError("create eBPF maps", err)
	}
	maps := make(map[string]*CiliumEBPF.Map, len(collection.Maps))
	for name, mapInstance := range collection.Maps {
		maps[name] = mapInstance
		delete(collection.Maps, name)
	}
	collection.Close()
	return maps, nil
}

func loadObjectPrograms(
	loadSpec func() (*CiliumEBPF.CollectionSpec, error),
	maps map[string]*CiliumEBPF.Map,
	selections []programSelection,
) ([]*CiliumEBPF.Program, error) {
	return loadObjectProgramsWithOptions(loadSpec, maps, selections, CiliumEBPF.ProgramOptions{})
}

func loadObjectProgramsWithOptions(
	loadSpec func() (*CiliumEBPF.CollectionSpec, error),
	maps map[string]*CiliumEBPF.Map,
	selections []programSelection,
	programOptions CiliumEBPF.ProgramOptions,
) ([]*CiliumEBPF.Program, error) {
	spec, err := loadSpec()
	if err != nil {
		return nil, E.Cause(err, "parse eBPF object")
	}
	selectedSections := make(map[string]int, len(selections))
	for index, selection := range selections {
		selectedSections[selection.section] = index
	}
	programSymbols := make([]string, len(selections))
	for symbol, program := range spec.Programs {
		index, selected := selectedSections[program.SectionName]
		if !selected {
			delete(spec.Programs, symbol)
			continue
		}
		if program.Type == CiliumEBPF.UnspecifiedProgram {
			return nil, E.New("eBPF program section has unknown type: ", program.SectionName)
		}
		program.Name = selections[index].name
		programSymbols[index] = symbol
	}
	for index, symbol := range programSymbols {
		if symbol == "" {
			return nil, E.New("eBPF object is missing program section ", selections[index].section)
		}
	}
	for name := range spec.Maps {
		if maps[name] == nil {
			delete(spec.Maps, name)
		}
	}
	for name, mapInstance := range maps {
		mapSpec := spec.Maps[name]
		if mapSpec == nil {
			return nil, E.New("eBPF object is missing map ", name)
		}
		info, infoErr := mapInstance.Info()
		if infoErr != nil {
			return nil, E.Cause(infoErr, "inspect replacement eBPF map ", name)
		}
		mapSpec.Type = info.Type
		mapSpec.KeySize = info.KeySize
		mapSpec.ValueSize = info.ValueSize
		mapSpec.MaxEntries = info.MaxEntries
		mapSpec.Flags = info.Flags
		mapSpec.Extra = nil
	}
	collection, err := CiliumEBPF.NewCollectionWithOptions(spec, CiliumEBPF.CollectionOptions{
		MapReplacements: maps,
		Programs:        programOptions,
	})
	if err != nil {
		return nil, eBPFOperationError("load eBPF programs", err)
	}
	programs := make([]*CiliumEBPF.Program, len(selections))
	for index, symbol := range programSymbols {
		programs[index] = collection.DetachProgram(symbol)
		if programs[index] == nil {
			_ = closePrograms(programs)
			collection.Close()
			return nil, E.New("loaded eBPF collection is missing program ", symbol)
		}
	}
	collection.Close()
	return programs, nil
}

func closePrograms(programs []*CiliumEBPF.Program) error {
	var closeErr error
	for index, program := range slices.Backward(programs) {
		if program == nil {
			continue
		}
		closeErr = E.Errors(closeErr, program.Close())
		programs[index] = nil
	}
	return closeErr
}

func closeMaps(maps map[string]*CiliumEBPF.Map) error {
	var closeErr error
	for name, mapInstance := range maps {
		if mapInstance == nil {
			continue
		}
		closeErr = E.Errors(closeErr, mapInstance.Close())
		delete(maps, name)
	}
	return closeErr
}
