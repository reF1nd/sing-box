//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"slices"
	"sync"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	CiliumEBPF "github.com/cilium/ebpf"
)

const (
	tcProgramLocalEgressEthernet = iota
	tcProgramLocalEgressRawIP
	tcProgramSharedIngressEthernet
	tcProgramSharedIngressRawIP
	tcProgramDeliveryIngress
	tcProgramCount
)

const (
	tcAssignmentCapacity = 65536
	tcPortPolicyCapacity = 4096
)

// DefaultTCRoutingMark is used only by standalone backend tests and callers
// that do not install policy routing. The TC data plane selects a free mark
// before enabling the backend.
const DefaultTCRoutingMark uint32 = 1 << 29

const (
	tcFlagIPv4 = 1 << iota
	tcFlagLocalIPv6
	tcFlagTCP
	tcFlagUDP
)

const tcFlagSharedIPv6 = 1 << 18
const (
	tcFlagLocalBypassPort  = 1 << 20
	tcFlagSharedBypassPort = 1 << 21
)

const (
	tcListenerTCP4 = iota
	tcListenerTCP6
)

const (
	TCPathShared   = 1
	TCPathDelivery = 2
)

type TCConfig struct {
	ListenerPort      uint16
	EnableLocal       bool
	EnableShared      bool
	EnableIPv4        bool
	EnableLocalIPv6   bool
	EnableSharedIPv6  bool
	EnableTCP         bool
	EnableUDP         bool
	DeliveryInterface uint32
	Policy            CompiledPolicy
	RoutingMark       uint32
	SelfBypassMap     *CiliumEBPF.Map
	TrackProcess      bool
}

type PortRange struct {
	Start uint16
	End   uint16
}

type tcPortKey struct {
	Protocol uint8
	Reserved uint8
	Port     uint16
}

type tcControl struct {
	Enabled           uint32
	Flags             uint32
	DeliveryInterface uint32
	RoutingMark       uint32
	ListenerPort      uint16
	LocalDNSMode      DNSMode
	SharedDNSMode     DNSMode
	DeliveryMAC       MACAddress
	Reserved          uint16
	FakeIPIPv4Prefix  [4]byte
	FakeIPIPv4Mask    [4]byte
	FakeIPIPv6Prefix  [16]byte
	FakeIPIPv6Mask    [16]byte
}

type tcAssignKey struct {
	Family             uint8
	Protocol           uint8
	SourcePort         uint16
	DestinationPort    uint16
	Reserved           uint16
	InterfaceIndex     uint32
	SourceAddress      [16]byte
	DestinationAddress [16]byte
}

type TCAssignment struct {
	SocketCookie   uint64
	InterfaceIndex uint32
	SourceMAC      MACAddress
	Path           uint8
	SourceMACValid uint8
}

type tcRuntime struct {
	maps     map[string]*CiliumEBPF.Map
	programs []*CiliumEBPF.Program
}

type TCBackend struct {
	access          sync.RWMutex
	runtime         *tcRuntime
	tcpListenerMap  bool
	control         tcControl
	controlMapFD    int
	assignmentMapFD int
	selfMapExternal bool
	bypassIPv4      []netip.Prefix
	bypassIPv6      []netip.Prefix
	hostIPv4        [][4]byte
	hostIPv6        [][16]byte
}

func PrepareTC(config TCConfig) (*TCBackend, error) {
	return prepareTC(config, false)
}

func prepareTC(config TCConfig, forceLegacyTCP bool) (*TCBackend, error) {
	if config.ListenerPort == 0 {
		return nil, E.New("invalid TC eBPF listener port")
	}
	if !config.EnableIPv4 && !config.EnableLocalIPv6 && !config.EnableSharedIPv6 {
		return nil, E.New("TC eBPF backend has no enabled address family")
	}
	if !config.EnableTCP && !config.EnableUDP {
		return nil, E.New("TC eBPF backend has no enabled protocol")
	}
	if !config.EnableLocal && !config.EnableShared {
		return nil, E.New("TC eBPF backend has no enabled data path")
	}
	if config.RoutingMark == 0 {
		config.RoutingMark = DefaultTCRoutingMark
	}
	policy := config.Policy
	var err error
	uidEntries := policy.uidEntries
	fakeIPIPv4 := policy.fakeIPIPv4
	fakeIPIPv6 := policy.fakeIPIPv6
	includeIPv4, includeIPv6 := policy.includeSource.ipv4, policy.includeSource.ipv6
	excludeIPv4, excludeIPv6 := policy.excludeSource.ipv4, policy.excludeSource.ipv6
	if err = checkLPMTriePolicyCompatibility(
		"TC eBPF UID and source CIDR",
		len(uidEntries)+len(includeIPv4)+len(includeIPv6)+len(excludeIPv4)+len(excludeIPv6),
	); err != nil {
		return nil, err
	}
	_ = raiseMemlockLimit()
	mapOverrides := map[string]mapSpecOverride{
		"tc_control":             {name: "sb_tc_ctl", mapType: CiliumEBPF.Array, maxEntries: 1},
		"tc_listener_sockets":    {name: "sb_tc_listen", mapType: CiliumEBPF.SockMap, maxEntries: 2},
		"tc_assignment":          {name: "sb_tc_assign", mapType: CiliumEBPF.LRUHash, maxEntries: tcAssignmentCapacity},
		"tc_uid_policy":          {name: "sb_tc_uid", mapType: CiliumEBPF.LPMTrie, maxEntries: max(uint32(len(uidEntries)), 1), flags: bpfFlagNoPrealloc},
		"tc_bypass_ipv4":         {name: "sb_tc_bypass4", mapType: CiliumEBPF.LPMTrie, maxEntries: maxBypassCIDRPolicyEntries, flags: bpfFlagNoPrealloc},
		"tc_bypass_ipv6":         {name: "sb_tc_bypass6", mapType: CiliumEBPF.LPMTrie, maxEntries: maxBypassCIDRPolicyEntries, flags: bpfFlagNoPrealloc},
		"tc_include_source_ipv4": {name: "sb_tc_insrc4", mapType: CiliumEBPF.LPMTrie, maxEntries: max(uint32(len(includeIPv4)), 1), flags: bpfFlagNoPrealloc},
		"tc_include_source_ipv6": {name: "sb_tc_insrc6", mapType: CiliumEBPF.LPMTrie, maxEntries: max(uint32(len(includeIPv6)), 1), flags: bpfFlagNoPrealloc},
		"tc_exclude_source_ipv4": {name: "sb_tc_exsrc4", mapType: CiliumEBPF.LPMTrie, maxEntries: max(uint32(len(excludeIPv4)), 1), flags: bpfFlagNoPrealloc},
		"tc_exclude_source_ipv6": {name: "sb_tc_exsrc6", mapType: CiliumEBPF.LPMTrie, maxEntries: max(uint32(len(excludeIPv6)), 1), flags: bpfFlagNoPrealloc},
		"tc_include_source_mac":  {name: "sb_tc_insmac", mapType: CiliumEBPF.Hash, maxEntries: sourceMACMapCapacity(len(policy.includeSourceMAC))},
		"tc_exclude_source_mac":  {name: "sb_tc_exsmac", mapType: CiliumEBPF.Hash, maxEntries: sourceMACMapCapacity(len(policy.excludeSourceMAC))},
		"tc_host_ipv4":           {name: "sb_tc_host4", mapType: CiliumEBPF.Hash, maxEntries: maxHostAddressPolicyEntries},
		"tc_host_ipv6":           {name: "sb_tc_host6", mapType: CiliumEBPF.Hash, maxEntries: maxHostAddressPolicyEntries},
		"tc_local_bypass_port":   {name: "sb_tc_lport", mapType: CiliumEBPF.Hash, maxEntries: tcPortPolicyCapacity},
		"tc_shared_bypass_port":  {name: "sb_tc_sport", mapType: CiliumEBPF.Hash, maxEntries: tcPortPolicyCapacity},
	}
	if config.EnableLocal {
		mapOverrides["tc_self_sockets"] = mapSpecOverride{
			name: "sb_self_sockets", mapType: CiliumEBPF.LRUHash, maxEntries: selfBypassSocketCapacity,
		}
	}
	legacyTCP := forceLegacyTCP || !config.EnableTCP
	maps, loadedPrograms, err := loadTCResources(config, mapOverrides, legacyTCP)
	if err != nil && config.EnableTCP && !forceLegacyTCP {
		legacyTCP = true
		maps, loadedPrograms, err = loadTCResources(config, mapOverrides, true)
	}
	if err != nil {
		return nil, err
	}
	controlValue := tcControl{
		Flags:             tcFlags(config, policy),
		DeliveryInterface: config.DeliveryInterface,
		RoutingMark:       config.RoutingMark,
		ListenerPort:      config.ListenerPort,
		LocalDNSMode:      policy.local.DNSMode,
		SharedDNSMode:     policy.sharedDNSMode,
	}
	if len(includeIPv4)+len(includeIPv6) > 0 {
		controlValue.Flags |= 1 << 12
	}
	if len(excludeIPv4)+len(excludeIPv6) > 0 {
		controlValue.Flags |= 1 << 13
	}
	if len(policy.includeSourceMAC) > 0 {
		controlValue.Flags |= 1 << 14
	}
	if len(policy.excludeSourceMAC) > 0 {
		controlValue.Flags |= 1 << 15
	}
	if fakeIPIPv4.IsValid() {
		controlValue.Flags |= 1 << 10
		controlValue.FakeIPIPv4Prefix = fakeIPIPv4.Addr().As4()
		controlValue.FakeIPIPv4Mask = prefixMask4(fakeIPIPv4.Bits())
	}
	if fakeIPIPv6.IsValid() {
		controlValue.Flags |= 1 << 11
		controlValue.FakeIPIPv6Prefix = fakeIPIPv6.Addr().As16()
		controlValue.FakeIPIPv6Mask = prefixMask16(fakeIPIPv6.Bits())
	}
	backend := &TCBackend{
		runtime:         &tcRuntime{maps: maps, programs: loadedPrograms},
		tcpListenerMap:  config.EnableTCP && !legacyTCP,
		control:         controlValue,
		controlMapFD:    maps["tc_control"].FD(),
		assignmentMapFD: maps["tc_assignment"].FD(),
		selfMapExternal: config.EnableLocal && config.SelfBypassMap != nil,
	}
	if err = backend.updateControlLocked(); err != nil {
		_ = backend.Close()
		return nil, err
	}
	if err = populateCompiledPolicyMaps(policyMapTargets{
		Scope:             "TC eBPF",
		UID:               maps["tc_uid_policy"],
		LocalPort:         maps["tc_local_bypass_port"],
		SharedPort:        maps["tc_shared_bypass_port"],
		IncludeSourceIPv4: maps["tc_include_source_ipv4"],
		IncludeSourceIPv6: maps["tc_include_source_ipv6"],
		ExcludeSourceIPv4: maps["tc_exclude_source_ipv4"],
		ExcludeSourceIPv6: maps["tc_exclude_source_ipv6"],
		IncludeSourceMAC:  maps["tc_include_source_mac"],
		ExcludeSourceMAC:  maps["tc_exclude_source_mac"],
	}, policy); err != nil {
		_ = backend.Close()
		return nil, err
	}
	return backend, nil
}

func loadTCResources(config TCConfig, baseOverrides map[string]mapSpecOverride, legacyTCP bool) (map[string]*CiliumEBPF.Map, []*CiliumEBPF.Program, error) {
	mapOverrides := make(map[string]mapSpecOverride, len(baseOverrides))
	for name, override := range baseOverrides {
		mapOverrides[name] = override
	}
	if legacyTCP {
		delete(mapOverrides, "tc_listener_sockets")
	}
	maps, err := loadObjectMaps(loadTC, mapOverrides)
	if err != nil {
		return nil, nil, err
	}
	externalSelfMap := config.EnableLocal && config.SelfBypassMap != nil
	if externalSelfMap {
		createdMap := maps["tc_self_sockets"]
		maps["tc_self_sockets"] = config.SelfBypassMap
		_ = createdMap.Close()
	}
	selections := make([]programSelection, 0, tcProgramCount)
	programIndexes := make([]int, 0, tcProgramCount)
	if config.EnableLocal {
		localEthernetSection := "classifier/local_egress_ethernet_mark"
		localRawIPSection := "classifier/local_egress_raw_ip_mark"
		if config.TrackProcess {
			localEthernetSection = "classifier/local_egress_ethernet_process"
			localRawIPSection = "classifier/local_egress_raw_ip_process"
		}
		selections = append(selections,
			programSelection{section: localEthernetSection, name: "sb_tc_local_l2"},
			programSelection{section: localRawIPSection, name: "sb_tc_local_l3"},
		)
		programIndexes = append(programIndexes, tcProgramLocalEgressEthernet, tcProgramLocalEgressRawIP)
	}
	if config.EnableShared {
		sharedEthernetSection := "classifier/shared_ingress_ethernet"
		sharedRawIPSection := "classifier/shared_ingress_raw_ip"
		if !config.EnableTCP {
			sharedEthernetSection += "_udp"
			sharedRawIPSection += "_udp"
		} else if legacyTCP {
			sharedEthernetSection += "_legacy"
			sharedRawIPSection += "_legacy"
		}
		selections = append(selections,
			programSelection{section: sharedEthernetSection, name: "sb_tc_share_l2"},
			programSelection{section: sharedRawIPSection, name: "sb_tc_share_l3"},
		)
		programIndexes = append(programIndexes, tcProgramSharedIngressEthernet, tcProgramSharedIngressRawIP)
	}
	if config.EnableLocal {
		deliverySection := "classifier/delivery_ingress"
		if !config.EnableTCP {
			deliverySection += "_udp"
		} else if legacyTCP {
			deliverySection += "_legacy"
		}
		selections = append(selections, programSelection{section: deliverySection, name: "sb_tc_deliver"})
		programIndexes = append(programIndexes, tcProgramDeliveryIngress)
	}
	loadedPrograms, err := loadObjectPrograms(loadTC, maps, selections)
	if err != nil {
		if externalSelfMap {
			delete(maps, "tc_self_sockets")
		}
		_ = closeMaps(maps)
		return nil, nil, err
	}
	programs := make([]*CiliumEBPF.Program, tcProgramCount)
	for index, program := range loadedPrograms {
		programs[programIndexes[index]] = program
	}
	return maps, programs, nil
}

func (b *TCBackend) SetRoutingMark(mark uint32) error {
	if mark == 0 {
		return E.New("invalid TC eBPF routing mark")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	previous := b.control.RoutingMark
	b.control.RoutingMark = mark
	if err := b.updateControlLocked(); err != nil {
		b.control.RoutingMark = previous
		return err
	}
	return nil
}

func tcFlags(config TCConfig, policy CompiledPolicy) uint32 {
	return policyVector{
		EnableTCP:           config.EnableTCP,
		EnableUDP:           config.EnableUDP,
		EnableIPv4:          config.EnableIPv4,
		EnableLocalIPv6:     config.EnableLocalIPv6,
		EnableSharedIPv6:    config.EnableSharedIPv6,
		UIDPolicy:           len(policy.uidEntries) > 0 || policy.uidDefaultBypass,
		UIDDefaultBypass:    policy.uidDefaultBypass,
		LocalBypassPrivate:  policy.local.BypassPrivateAddress,
		SharedBypassPrivate: policy.sharedBypassPrivate,
		LocalBypassPort:     len(policy.localBypassPortEntries) > 0,
		SharedBypassPort:    len(policy.sharedBypassPortEntries) > 0,
		FakeIPIPv4:          policy.fakeIPIPv4.IsValid(),
		FakeIPIPv6:          policy.fakeIPIPv6.IsValid(),
		IncludeSource:       len(policy.includeSource.ipv4)+len(policy.includeSource.ipv6) > 0,
		ExcludeSource:       len(policy.excludeSource.ipv4)+len(policy.excludeSource.ipv6) > 0,
		IncludeSourceMAC:    len(policy.includeSourceMAC) > 0,
		ExcludeSourceMAC:    len(policy.excludeSourceMAC) > 0,
	}.tcFlags()
}

func (b *TCBackend) updateControlLocked() error {
	key := uint32(0)
	if err := updateMap(b.controlMapFD, unsafe.Pointer(&key), unsafe.Pointer(&b.control)); err != nil {
		return eBPFOperationError("update TC eBPF control", err)
	}
	return nil
}

func (b *TCBackend) Enable() error {
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	previousEnabled := b.control.Enabled
	b.control.Enabled = 1
	if err := b.updateControlLocked(); err != nil {
		b.control.Enabled = previousEnabled
		return err
	}
	return nil
}

func (b *TCBackend) Disable() error {
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	previousEnabled := b.control.Enabled
	b.control.Enabled = 0
	if err := b.updateControlLocked(); err != nil {
		b.control.Enabled = previousEnabled
		return err
	}
	return nil
}

func (b *TCBackend) SetDeliveryInterface(interfaceIndex uint32, hardwareAddress MACAddress) error {
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	previousInterface := b.control.DeliveryInterface
	previousHardwareAddress := b.control.DeliveryMAC
	b.control.DeliveryInterface = interfaceIndex
	b.control.DeliveryMAC = hardwareAddress
	if err := b.updateControlLocked(); err != nil {
		b.control.DeliveryInterface = previousInterface
		b.control.DeliveryMAC = previousHardwareAddress
		return err
	}
	return nil
}

func (b *TCBackend) RegisterTCPListener(ipv6 bool, fd int) error {
	if !b.tcpListenerMap {
		return nil
	}
	if fd < 0 {
		return E.New("invalid TC eBPF listener socket")
	}
	key := uint32(tcListenerTCP4)
	if ipv6 {
		key = tcListenerTCP6
	}
	value := uint32(fd)
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	if err := updateMap(b.runtime.maps["tc_listener_sockets"].FD(), unsafe.Pointer(&key), unsafe.Pointer(&value)); err != nil {
		return E.Cause(err, "register TC eBPF TCP listener")
	}
	return nil
}

func (b *TCBackend) TCPListenerLookupMode() string {
	b.access.RLock()
	defer b.access.RUnlock()
	if b.tcpListenerMap {
		return "sockmap"
	}
	return "direct"
}

func (b *TCBackend) LookupAssignment(protocol uint8, source, destination netip.AddrPort, interfaceIndex uint32, remove bool) (TCAssignment, error) {
	key, err := makeTCAssignKey(protocol, source, destination, interfaceIndex)
	if err != nil {
		return TCAssignment{}, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return TCAssignment{}, errBackendClosed
	}
	var assignment TCAssignment
	if err = lookupMap(b.assignmentMapFD, unsafe.Pointer(&key), unsafe.Pointer(&assignment)); err != nil {
		return TCAssignment{}, err
	}
	if remove {
		_ = deleteMap(b.assignmentMapFD, unsafe.Pointer(&key))
	}
	return assignment, nil
}

func (b *TCBackend) UpdateCompiledBypassCIDR(policy BypassCIDRPolicy) (bool, error) {
	if len(policy.ipv4) > maxBypassCIDRPolicyEntries || len(policy.ipv6) > maxBypassCIDRPolicyEntries {
		return false, E.New("TC eBPF bypass CIDR policy exceeds map capacity")
	}
	if err := checkLPMTriePolicyCompatibility("TC eBPF bypass CIDR", len(policy.ipv4)+len(policy.ipv6)); err != nil {
		return false, err
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return false, errBackendClosed
	}
	changed, err := replaceDualStackCIDRPolicy(
		b.runtime.maps["tc_bypass_ipv4"],
		b.runtime.maps["tc_bypass_ipv6"],
		dualStackCIDRPrefixes{b.bypassIPv4, b.bypassIPv6},
		dualStackCIDRPrefixes(policy),
		"TC ",
		"bypass CIDR",
	)
	if err != nil {
		return false, err
	}
	b.bypassIPv4 = slices.Clone(policy.ipv4)
	b.bypassIPv6 = slices.Clone(policy.ipv6)
	if len(b.bypassIPv4) > 0 {
		b.control.Flags |= 1 << 8
	} else {
		b.control.Flags &^= 1 << 8
	}
	if len(b.bypassIPv6) > 0 {
		b.control.Flags |= 1 << 9
	} else {
		b.control.Flags &^= 1 << 9
	}
	if err = b.updateControlLocked(); err != nil {
		return false, err
	}
	return changed, nil
}

func (b *TCBackend) UpdateHostAddresses(addresses []netip.Addr) error {
	if b == nil {
		return errBackendClosed
	}
	ipv4, ipv6 := compileHostAddresses(addresses)
	if len(ipv4) > maxHostAddressPolicyEntries || len(ipv6) > maxHostAddressPolicyEntries {
		return E.New("TC eBPF host address policy exceeds map capacity")
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	err := replaceHostAddressPolicy(
		b.runtime.maps["tc_host_ipv4"],
		b.runtime.maps["tc_host_ipv6"],
		b.hostIPv4,
		b.hostIPv6,
		ipv4,
		ipv6,
	)
	if err != nil {
		return err
	}
	b.hostIPv4 = slices.Clone(ipv4)
	b.hostIPv6 = slices.Clone(ipv6)
	if len(b.hostIPv4) > 0 {
		b.control.Flags |= 1 << 16
	} else {
		b.control.Flags &^= 1 << 16
	}
	if len(b.hostIPv6) > 0 {
		b.control.Flags |= 1 << 17
	} else {
		b.control.Flags &^= 1 << 17
	}
	return b.updateControlLocked()
}

func makeTCAssignKey(protocol uint8, source, destination netip.AddrPort, interfaceIndex uint32) (tcAssignKey, error) {
	var key tcAssignKey
	if !source.IsValid() || !destination.IsValid() || source.Addr().Is4() != destination.Addr().Is4() {
		return key, E.New("invalid TC eBPF assignment tuple")
	}
	key.Protocol = protocol
	key.SourcePort = source.Port()
	key.DestinationPort = destination.Port()
	key.InterfaceIndex = interfaceIndex
	if source.Addr().Is4() {
		key.Family = addressFamilyIPv4
		source4 := source.Addr().As4()
		destination4 := destination.Addr().As4()
		copy(key.SourceAddress[:4], source4[:])
		copy(key.DestinationAddress[:4], destination4[:])
	} else {
		key.Family = addressFamilyIPv6
		key.SourceAddress = source.Addr().As16()
		key.DestinationAddress = destination.Addr().As16()
	}
	return key, nil
}

func (b *TCBackend) LocalEgressProgramFD(framing TCLinkFraming) int {
	switch framing {
	case TCLinkFramingEthernet:
		return b.programFD(tcProgramLocalEgressEthernet)
	case TCLinkFramingRawIP:
		return b.programFD(tcProgramLocalEgressRawIP)
	default:
		return -1
	}
}

func (b *TCBackend) LocalEgressProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	switch framing {
	case TCLinkFramingEthernet:
		return b.program(tcProgramLocalEgressEthernet)
	case TCLinkFramingRawIP:
		return b.program(tcProgramLocalEgressRawIP)
	default:
		return nil
	}
}

func (b *TCBackend) SharedIngressProgramFD(framing TCLinkFraming) int {
	switch framing {
	case TCLinkFramingEthernet:
		return b.programFD(tcProgramSharedIngressEthernet)
	case TCLinkFramingRawIP:
		return b.programFD(tcProgramSharedIngressRawIP)
	default:
		return -1
	}
}

func (b *TCBackend) SharedIngressProgram(framing TCLinkFraming) *CiliumEBPF.Program {
	switch framing {
	case TCLinkFramingEthernet:
		return b.program(tcProgramSharedIngressEthernet)
	case TCLinkFramingRawIP:
		return b.program(tcProgramSharedIngressRawIP)
	default:
		return nil
	}
}

func (b *TCBackend) DeliveryIngressProgramFD() int { return b.programFD(tcProgramDeliveryIngress) }

func (b *TCBackend) programFD(index int) int {
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || index < 0 || index >= len(b.runtime.programs) || b.runtime.programs[index] == nil {
		return -1
	}
	return b.runtime.programs[index].FD()
}

func (b *TCBackend) program(index int) *CiliumEBPF.Program {
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil || index < 0 || index >= len(b.runtime.programs) {
		return nil
	}
	return b.runtime.programs[index]
}

func (b *TCBackend) Close() error {
	if b == nil {
		return nil
	}
	b.access.Lock()
	defer b.access.Unlock()
	if b.runtime == nil {
		return nil
	}
	b.control.Enabled = 0
	_ = b.updateControlLocked()
	var closeErr error
	closeErr = E.Errors(closeErr, closePrograms(b.runtime.programs))
	if b.selfMapExternal {
		delete(b.runtime.maps, "tc_self_sockets")
	}
	closeErr = E.Errors(closeErr, closeMaps(b.runtime.maps))
	b.runtime = nil
	b.controlMapFD = -1
	b.assignmentMapFD = -1
	b.selfMapExternal = false
	b.bypassIPv4 = nil
	b.bypassIPv6 = nil
	b.hostIPv4 = nil
	b.hostIPv6 = nil
	return closeErr
}
