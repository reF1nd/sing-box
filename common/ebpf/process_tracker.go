//go:build with_ebpf && (linux || android)

package ebpf

import (
	"slices"

	CiliumEBPF "github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
	"github.com/cilium/ebpf/link"
	E "github.com/sagernet/sing/common/exceptions"
)

const processSocketOwnerCapacity = 65536

const (
	socketMetadataPolicyBypass    = SocketMetadataPolicyBypass
	socketMetadataPolicyIntercept = SocketMetadataPolicyIntercept
)

type ProcessTrackerConfig struct {
	EnableTCP   bool
	EnableUDP   bool
	EnableIPv6  bool
	LocalPolicy LocalPolicy
	MetadataMap *CiliumEBPF.Map
}

type ProcessSocketOwner struct {
	ProcessID uint32
	UserID    uint32
}

type processTrackerHook struct {
	name       string
	attachType CiliumEBPF.AttachType
}

// ProcessTracker records the process performing connect or UDP sendmsg for a
// socket. Socket cookies let the TC data path carry that identity to userspace
// without searching every process file descriptor under procfs.
type ProcessTracker struct {
	owners              *CiliumEBPF.Map
	policyUID           *CiliumEBPF.Map
	metadata            *CiliumEBPF.Map
	policyDefaultBypass bool
	programs            []*CiliumEBPF.Program
	links               []link.Link
}

func AttachProcessTracker(config ProcessTrackerConfig) (*ProcessTracker, error) {
	if !config.EnableTCP && !config.EnableUDP {
		return nil, E.New("process tracker has no enabled protocol")
	}
	_ = raiseMemlockLimit()
	cgroupPath, err := DetectCgroup2Root()
	if err != nil {
		return nil, E.Cause(err, "detect cgroup v2 root")
	}
	owners, err := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
		Name:       "sb_proc_owner",
		Type:       CiliumEBPF.LRUHash,
		KeySize:    8,
		ValueSize:  8,
		MaxEntries: processSocketOwnerCapacity,
	})
	if err != nil {
		return nil, E.Cause(err, "create eBPF process owner map")
	}
	uidEntries, defaultBypass, err := compileUIDPolicy(config.LocalPolicy)
	if err != nil {
		_ = owners.Close()
		return nil, err
	}
	tracker := &ProcessTracker{
		owners: owners,
	}
	if len(uidEntries) > 0 || defaultBypass {
		uidPolicy, mapErr := CiliumEBPF.NewMap(&CiliumEBPF.MapSpec{
			Name:       "sb_proc_uid",
			Type:       CiliumEBPF.LPMTrie,
			KeySize:    8,
			ValueSize:  1,
			MaxEntries: max(uint32(len(uidEntries)), 1),
			Flags:      bpfFlagNoPrealloc,
		})
		if mapErr != nil {
			_ = owners.Close()
			return nil, E.Cause(mapErr, "create eBPF process UID policy map")
		}
		if mapErr = populateUIDPolicyMap(uidPolicy, uidEntries); mapErr != nil {
			_ = uidPolicy.Close()
			_ = owners.Close()
			return nil, E.Cause(mapErr, "populate eBPF process UID policy map")
		}
		if config.MetadataMap == nil {
			_ = uidPolicy.Close()
			_ = owners.Close()
			return nil, E.New("eBPF socket metadata map is unavailable")
		}
		tracker.metadata = config.MetadataMap
		tracker.policyUID = uidPolicy
		tracker.policyDefaultBypass = defaultBypass
	}
	complete := false
	defer func() {
		if !complete {
			_ = tracker.Close()
		}
	}()
	for _, hook := range processTrackerHooks(config) {
		program, loadErr := newProcessTrackerProgram(hook, owners.FD(), tracker.policyUIDFD(), tracker.metadataFD(), tracker.policyDefaultBypass)
		if loadErr != nil {
			return nil, loadErr
		}
		tracker.programs = append(tracker.programs, program)
		programLink, attachErr := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  hook.attachType,
			Program: program,
		})
		if attachErr != nil {
			return nil, E.Cause(attachErr, "attach eBPF process tracker ", hook.name, " hook")
		}
		tracker.links = append(tracker.links, programLink)
	}
	complete = true
	return tracker, nil
}

func processTrackerHooks(config ProcessTrackerConfig) []processTrackerHook {
	var hooks []processTrackerHook
	if config.EnableTCP {
		hooks = append(hooks, processTrackerHook{"connect4", CiliumEBPF.AttachCGroupInet4Connect})
		if config.EnableIPv6 {
			hooks = append(hooks, processTrackerHook{"connect6", CiliumEBPF.AttachCGroupInet6Connect})
		}
	}
	if config.EnableUDP {
		hooks = append(hooks, processTrackerHook{"sendmsg4", CiliumEBPF.AttachCGroupUDP4Sendmsg})
		if config.EnableIPv6 {
			hooks = append(hooks, processTrackerHook{"sendmsg6", CiliumEBPF.AttachCGroupUDP6Sendmsg})
		}
	}
	return hooks
}

func newProcessTrackerProgram(hook processTrackerHook, ownerMapFD, policyUIDMapFD, metadataMapFD int, defaultBypass bool) (*CiliumEBPF.Program, error) {
	program, err := CiliumEBPF.NewProgram(&CiliumEBPF.ProgramSpec{
		Name:         "sb_proc_" + hook.name,
		Type:         CiliumEBPF.CGroupSockAddr,
		AttachType:   hook.attachType,
		License:      "GPL",
		Instructions: processTrackerInstructions(ownerMapFD, policyUIDMapFD, metadataMapFD, defaultBypass),
	})
	if err != nil {
		return nil, E.Cause(err, "load eBPF process tracker ", hook.name, " hook")
	}
	return program, nil
}

func processTrackerInstructions(ownerMapFD, policyUIDMapFD, metadataMapFD int, defaultBypass bool) asm.Instructions {
	instructions := asm.Instructions{
		asm.FnGetSocketCookie.Call(),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.StoreMem(asm.RFP, -8, asm.R0, asm.DWord),
		asm.FnGetCurrentPidTgid.Call(),
		asm.RSh.Imm(asm.R0, 32),
		asm.JEq.Imm(asm.R0, 0, "allow"),
		asm.StoreMem(asm.RFP, -16, asm.R0, asm.Word),
		asm.FnGetCurrentUidGid.Call(),
		asm.StoreMem(asm.RFP, -12, asm.R0, asm.Word),
		asm.LoadMapPtr(asm.R1, ownerMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "update_owner"),
		asm.Mov.Reg(asm.R6, asm.R0),
		asm.LoadMem(asm.R1, asm.R6, 0, asm.Word),
		asm.LoadMem(asm.R2, asm.RFP, -16, asm.Word),
		asm.JNE.Reg(asm.R1, asm.R2, "update_owner"),
		asm.LoadMem(asm.R1, asm.R6, 4, asm.Word),
		asm.LoadMem(asm.R2, asm.RFP, -12, asm.Word),
		asm.JEq.Reg(asm.R1, asm.R2, "policy"),
		asm.LoadMapPtr(asm.R1, ownerMapFD).WithSymbol("update_owner"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -16),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Ja.Label("policy"),
	}
	if policyUIDMapFD < 0 || metadataMapFD < 0 {
		instructions = append(instructions,
			asm.Mov.Reg(asm.R0, asm.R0).WithSymbol("policy"),
			asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
			asm.Return(),
		)
		return instructions
	}
	instructions = append(instructions,
		asm.StoreImm(asm.RFP, -24, 32, asm.Word).WithSymbol("policy"),
		asm.LoadMapPtr(asm.R1, metadataMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "metadata_empty"),
		asm.LoadMem(asm.R0, asm.R0, 0, asm.Word),
		asm.And.Imm(asm.R0, SocketMetadataSelfBypass),
		asm.StoreMem(asm.RFP, -28, asm.R0, asm.Word),
		asm.Ja.Label("lookup_policy_uid"),
		asm.StoreImm(asm.RFP, -28, 0, asm.Word).WithSymbol("metadata_empty"),
		asm.LoadMem(asm.R0, asm.RFP, -12, asm.Word).WithSymbol("lookup_policy_uid"),
		asm.BSwap(asm.R0, asm.Word),
		asm.StoreMem(asm.RFP, -20, asm.R0, asm.Word),
		asm.LoadMapPtr(asm.R1, policyUIDMapFD),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -24),
		asm.FnMapLookupElem.Call(),
		asm.JEq.Imm(asm.R0, 0, "policy_unmatched"),
		asm.LoadMem(asm.R0, asm.RFP, -28, asm.Word),
		asm.Or.Imm(asm.R0, socketMetadataPolicyIntercept),
		asm.StoreMem(asm.RFP, -28, asm.R0, asm.Word),
		asm.Ja.Label("policy_update"),
		asm.LoadMem(asm.R0, asm.RFP, -28, asm.Word).WithSymbol("policy_unmatched"),
		asm.Or.Imm(asm.R0, int32(func() int64 {
			if defaultBypass {
				return socketMetadataPolicyBypass
			}
			return 0
		}())),
		asm.StoreMem(asm.RFP, -28, asm.R0, asm.Word),
		asm.LoadMapPtr(asm.R1, metadataMapFD).WithSymbol("policy_update"),
		asm.Mov.Reg(asm.R2, asm.RFP),
		asm.Add.Imm(asm.R2, -8),
		asm.Mov.Reg(asm.R3, asm.RFP),
		asm.Add.Imm(asm.R3, -28),
		asm.Mov.Imm(asm.R4, 0),
		asm.FnMapUpdateElem.Call(),
		asm.Mov.Imm(asm.R0, 1).WithSymbol("allow"),
		asm.Return(),
	)
	return instructions
}

func (t *ProcessTracker) policyUIDFD() int {
	if t == nil || t.policyUID == nil {
		return -1
	}
	return t.policyUID.FD()
}

func (t *ProcessTracker) metadataFD() int {
	if t == nil || t.metadata == nil {
		return -1
	}
	return t.metadata.FD()
}

func (t *ProcessTracker) LookupOwner(socketCookie uint64) (ProcessSocketOwner, error) {
	if t == nil || t.owners == nil || socketCookie == 0 {
		return ProcessSocketOwner{}, E.New("invalid eBPF process owner lookup")
	}
	var owner ProcessSocketOwner
	if err := t.owners.Lookup(&socketCookie, &owner); err != nil {
		return ProcessSocketOwner{}, err
	}
	return owner, nil
}

func (t *ProcessTracker) Close() error {
	if t == nil {
		return nil
	}
	var closeErr error
	for index, programLink := range slices.Backward(t.links) {
		if programLink == nil {
			continue
		}
		closeErr = E.Errors(closeErr, programLink.Close())
		t.links[index] = nil
	}
	for index, program := range slices.Backward(t.programs) {
		if program == nil {
			continue
		}
		closeErr = E.Errors(closeErr, program.Close())
		t.programs[index] = nil
	}
	if t.owners != nil {
		closeErr = E.Errors(closeErr, t.owners.Close())
		t.owners = nil
	}
	if t.policyUID != nil {
		closeErr = E.Errors(closeErr, t.policyUID.Close())
		t.policyUID = nil
	}
	return closeErr
}
