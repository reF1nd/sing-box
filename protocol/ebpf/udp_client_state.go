//go:build with_ebpf && (linux || android)

package ebpf

import (
	"context"
	"net"
	"net/netip"
	"sync"

	commonEBPF "github.com/CHIZI-0618/sing-ebpf"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

const (
	udpClientShardCount = 16
	udpReplyAliasLimit  = 64
)

type udpClientTable struct {
	clientShards     [udpClientShardCount]udpClientShard
	redirectAccess   sync.RWMutex
	redirectSessions map[udpRedirectSessionKey]udpClientReference
}

type udpClientReference struct {
	key   udpSessionKey
	state *udpClientState
}

type udpClientShard struct {
	access  sync.RWMutex
	clients map[udpSessionKey]*udpClientState
}

type udpRedirectSessionKey struct {
	client  netip.AddrPort
	address netip.Addr
}

type udpSessionScope uint8

const (
	udpSessionScopeLocalCgroup udpSessionScope = iota + 1
	udpSessionScopeLocalTC
	udpSessionScopeSharedTC
	udpSessionScopeSharedRewrite
)

// udpSessionKey keeps kernel identities which are stronger than the source
// address in the userspace association key. Source alone is ambiguous for
// SO_REUSEPORT sockets and when the same downstream address appears on more
// than one ingress interface.
type udpSessionKey struct {
	Source         netip.AddrPort
	Scope          udpSessionScope
	SocketCookie   uint64
	InterfaceIndex uint32
}

type udpNATContextKey struct{}

func udpSessionKeyFromContext(ctx context.Context) (udpSessionKey, bool) {
	key, loaded := ctx.Value(udpNATContextKey{}).(udpSessionKey)
	return key, loaded
}

type udpClientState struct {
	access          sync.RWMutex
	sourceMAC       net.HardwareAddr
	socketCookie    uint64
	bindings        map[netip.AddrPort]udpRedirectBinding
	replyAliasCount uint16
	closed          bool
	natOwned        bool
	cgroupDataPlane bool
	cgroupOriginals map[netip.Addr]commonEBPF.OriginalDestination
}

type udpRedirectBinding struct {
	replyAlias                    bool
	redirectAddress               netip.Addr
	packetInfo                    []byte
	connected                     bool
	tcAssignmentKeyInterfaceIndex uint32
	tcAssignmentKeyValid          bool
	tcAssignment                  commonEBPF.TCAssignment
	tcReturn                      commonEBPF.TCReturnHandle
}

type tcAssignmentCleanup struct {
	destination       netip.AddrPort
	keyInterfaceIndex uint32
	assignment        commonEBPF.TCAssignment
}

type udpSessionCleanup struct {
	cgroupRedirects []netip.Addr
	tcAssignments   []tcAssignmentCleanup
	tcReturns       []commonEBPF.TCReturnHandle
}

func (t *udpClientTable) load(key udpSessionKey) (*udpClientState, bool) {
	shard := t.clientShard(key)
	shard.access.RLock()
	state, loaded := shard.clients[key]
	shard.access.RUnlock()
	return state, loaded
}

func (t *udpClientTable) loadOrCreate(key udpSessionKey) *udpClientState {
	if state, loaded := t.load(key); loaded {
		return state
	}
	shard := t.clientShard(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	if state, loaded := shard.clients[key]; loaded {
		return state
	}
	if shard.clients == nil {
		shard.clients = make(map[udpSessionKey]*udpClientState)
	}
	state := &udpClientState{
		bindings:        make(map[netip.AddrPort]udpRedirectBinding),
		cgroupOriginals: make(map[netip.Addr]commonEBPF.OriginalDestination),
	}
	shard.clients[key] = state
	return state
}

func (t *udpClientTable) cachedCgroupOriginal(client netip.AddrPort, redirectAddress netip.Addr) (udpSessionKey, commonEBPF.OriginalDestination, bool) {
	lookupKey := udpRedirectSessionKey{client: client, address: redirectAddress}
	t.redirectAccess.RLock()
	reference, loaded := t.redirectSessions[lookupKey]
	t.redirectAccess.RUnlock()
	if !loaded {
		return udpSessionKey{}, commonEBPF.OriginalDestination{}, false
	}
	state, loaded := t.load(reference.key)
	if !loaded || state != reference.state {
		return udpSessionKey{}, commonEBPF.OriginalDestination{}, false
	}
	state.access.RLock()
	original, loaded := state.cgroupOriginals[redirectAddress]
	state.access.RUnlock()
	return reference.key, original, loaded
}

func (t *udpClientTable) setCgroupBinding(key udpSessionKey, original commonEBPF.OriginalDestination, redirectAddress netip.Addr) {
	state := t.loadOrCreate(key)
	state.access.Lock()
	state.cgroupOriginals[redirectAddress] = original
	state.socketCookie = original.SocketCookie
	state.cgroupDataPlane = true
	state.bindings[original.Destination] = udpRedirectBinding{
		redirectAddress: redirectAddress,
		packetInfo:      sourcePacketInfo(redirectAddress),
		connected:       original.ConnectedUDP,
	}
	state.access.Unlock()
	t.redirectAccess.Lock()
	if t.redirectSessions == nil {
		t.redirectSessions = make(map[udpRedirectSessionKey]udpClientReference)
	}
	t.redirectSessions[udpRedirectSessionKey{client: key.Source, address: redirectAddress}] = udpClientReference{key: key, state: state}
	t.redirectAccess.Unlock()
}

func (t *udpClientTable) setCgroupReplyBinding(key udpSessionKey, expected *udpClientState, destination netip.AddrPort, redirectAddress netip.Addr) bool {
	shard := t.clientShard(key)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[key] != expected {
		return false
	}
	expected.access.Lock()
	defer expected.access.Unlock()
	if expected.closed || expected.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	expected.cgroupOriginals[redirectAddress] = commonEBPF.OriginalDestination{Destination: destination}
	expected.cgroupDataPlane = true
	expected.bindings[destination] = udpRedirectBinding{
		replyAlias:      true,
		redirectAddress: redirectAddress,
		packetInfo:      sourcePacketInfo(redirectAddress),
	}
	expected.replyAliasCount++
	t.redirectAccess.Lock()
	if t.redirectSessions == nil {
		t.redirectSessions = make(map[udpRedirectSessionKey]udpClientReference)
	}
	t.redirectSessions[udpRedirectSessionKey{client: key.Source, address: redirectAddress}] = udpClientReference{key: key, state: expected}
	t.redirectAccess.Unlock()
	return true
}

func (t *udpClientTable) clientShard(key udpSessionKey) *udpClientShard {
	return &t.clientShards[shardIndexForAddrPort(key.Source, udpClientShardCount)]
}

// claimNATState gives a new NAT connection an independent state generation.
// Cache eviction and handler close are asynchronous relative to the next
// packet, so reusing the previous pointer would let old cleanup erase the new
// session's bindings. The old pointer remains addressable by its cleanup,
// while the shard now points at the new generation.
func (t *udpClientTable) claimNATState(key udpSessionKey) *udpClientState {
	shard := t.clientShard(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	if state, loaded := shard.clients[key]; loaded {
		state.access.Lock()
		owned := state.natOwned && !state.closed
		if !owned {
			state.natOwned = true
			state.access.Unlock()
			return state
		}
		newState := &udpClientState{
			natOwned:        true,
			sourceMAC:       append(net.HardwareAddr(nil), state.sourceMAC...),
			socketCookie:    state.socketCookie,
			bindings:        state.bindings,
			replyAliasCount: state.replyAliasCount,
			cgroupDataPlane: state.cgroupDataPlane,
			cgroupOriginals: state.cgroupOriginals,
		}
		state.closed = true
		state.bindings = make(map[netip.AddrPort]udpRedirectBinding)
		state.cgroupOriginals = make(map[netip.Addr]commonEBPF.OriginalDestination)
		state.replyAliasCount = 0
		state.access.Unlock()
		shard.clients[key] = newState
		t.redirectAccess.Lock()
		for redirectKey, reference := range t.redirectSessions {
			if reference.key == key && reference.state == state {
				t.redirectSessions[redirectKey] = udpClientReference{key: key, state: newState}
			}
		}
		t.redirectAccess.Unlock()
		return newState
	}
	if shard.clients == nil {
		shard.clients = make(map[udpSessionKey]*udpClientState)
	}
	state := &udpClientState{
		natOwned:        true,
		bindings:        make(map[netip.AddrPort]udpRedirectBinding),
		cgroupOriginals: make(map[netip.Addr]commonEBPF.OriginalDestination),
	}
	shard.clients[key] = state
	return state
}

// shardIndexForAddrPort distributes addr:port pairs across shardCount (a
// power of two) shards by hashing every address byte together with the
// port, not the port alone. A port-only key collapses onto a single shard
// whenever many distinct addresses happen to share one port -- exactly the
// common case for both callers of this function: UDP destinations
// overwhelmingly cluster on a handful of well-known ports (443, 53, ...)
// while varying in address, and independent client hosts can coincidentally
// reuse the same ephemeral source port for unrelated connections.
//
// This is a statistical improvement over the port-only key for realistic,
// naturally-varying traffic (see the package's shard-distribution tests),
// not a guarantee of even placement for every possible input set: FNV-1a is
// not a cryptographic hash, so a party able to choose destination addresses
// specifically to collide under it could still concentrate them onto one
// shard. This function only changes how inputs are distributed across
// shards. Reply socket capacity is global, independent of shard distribution.
func shardIndexForAddrPort(addrPort netip.AddrPort, shardCount int) int {
	const offset64 = 14695981039346656037
	const prime64 = 1099511628211
	hash := uint64(offset64)
	for _, b := range addrPort.Addr().As16() {
		hash ^= uint64(b)
		hash *= prime64
	}
	port := addrPort.Port()
	hash ^= uint64(port)
	hash *= prime64
	hash ^= uint64(port >> 8)
	hash *= prime64
	return int(hash & uint64(shardCount-1))
}

// count reports the number of tracked UDP clients, for diagnostics. It locks
// each shard in turn rather than all at once, so this is a point-in-time
// estimate under concurrent traffic, not a value consistent with any single
// instant -- adequate for a diagnostics counter, not for anything that would
// act on the exact number.
func (t *udpClientTable) count() int {
	total := 0
	for index := range t.clientShards {
		shard := &t.clientShards[index]
		shard.access.RLock()
		total += len(shard.clients)
		shard.access.RUnlock()
	}
	return total
}

func (t *udpClientTable) setDirectBinding(
	key udpSessionKey,
	destination netip.AddrPort,
	sourceMAC net.HardwareAddr,
	socketCookie uint64,
) {
	state := t.loadOrCreate(key)
	state.access.Lock()
	defer state.access.Unlock()
	if len(sourceMAC) > 0 {
		state.sourceMAC = append(state.sourceMAC[:0], sourceMAC...)
	}
	state.socketCookie = socketCookie
	state.bindings[destination] = udpRedirectBinding{}
}

func (t *udpClientTable) setDirectAssignmentBinding(
	key udpSessionKey,
	destination netip.AddrPort,
	sourceMAC net.HardwareAddr,
	assignmentKeyInterfaceIndex uint32,
	assignment commonEBPF.TCAssignment,
) {
	state := t.loadOrCreate(key)
	state.access.Lock()
	defer state.access.Unlock()
	if len(sourceMAC) > 0 {
		state.sourceMAC = append(state.sourceMAC[:0], sourceMAC...)
	}
	state.socketCookie = assignment.SocketCookie
	previous := state.bindings[destination]
	if previous.replyAlias {
		state.replyAliasCount--
	}
	state.bindings[destination] = udpRedirectBinding{
		tcReturn:                      previous.tcReturn,
		tcAssignmentKeyInterfaceIndex: assignmentKeyInterfaceIndex,
		tcAssignmentKeyValid:          true,
		tcAssignment:                  assignment,
	}
}

func (t *udpClientTable) setDirectReplyBinding(
	key udpSessionKey,
	expected *udpClientState,
	destination netip.AddrPort,
) bool {
	shard := t.clientShard(key)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[key] != expected {
		return false
	}
	expected.access.Lock()
	defer expected.access.Unlock()
	if expected.closed {
		return false
	}
	if _, loaded := expected.bindings[destination]; loaded {
		return true
	}
	if expected.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	expected.bindings[destination] = udpRedirectBinding{replyAlias: true}
	expected.replyAliasCount++
	return true
}

func (t *udpClientTable) delete(key udpSessionKey, expected *udpClientState) []netip.Addr {
	return t.deleteWithCleanup(key, expected).cgroupRedirects
}

func (t *udpClientTable) deleteWithCleanup(key udpSessionKey, expected *udpClientState) udpSessionCleanup {
	shard := t.clientShard(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	if shard.clients[key] == expected {
		delete(shard.clients, key)
	}
	expected.access.Lock()
	redirects := make([]netip.Addr, 0, len(expected.cgroupOriginals))
	for address := range expected.cgroupOriginals {
		redirects = append(redirects, address)
	}
	assignments := make([]tcAssignmentCleanup, 0, len(expected.bindings))
	var returns []commonEBPF.TCReturnHandle
	for destination, binding := range expected.bindings {
		if binding.tcReturn.IsValid() {
			returns = append(returns, binding.tcReturn)
		}
		if binding.tcAssignmentKeyValid {
			assignments = append(assignments, tcAssignmentCleanup{
				destination:       destination,
				keyInterfaceIndex: binding.tcAssignmentKeyInterfaceIndex,
				assignment:        binding.tcAssignment,
			})
		}
	}
	expected.closed = true
	clear(expected.bindings)
	clear(expected.cgroupOriginals)
	expected.cgroupDataPlane = false
	expected.replyAliasCount = 0
	expected.access.Unlock()
	t.redirectAccess.Lock()
	for _, address := range redirects {
		lookupKey := udpRedirectSessionKey{client: key.Source, address: address}
		if reference := t.redirectSessions[lookupKey]; reference.key == key && reference.state == expected {
			delete(t.redirectSessions, lookupKey)
		}
	}
	t.redirectAccess.Unlock()
	return udpSessionCleanup{cgroupRedirects: redirects, tcAssignments: assignments, tcReturns: returns}
}

// Retain once per destination, never once per packet. Taking the state lock
// also serializes this acquisition with session close and reply-alias creation.
func (s *udpClientState) retainTCReturn(backend *commonEBPF.TCBackend, client, destination netip.AddrPort) error {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return E.New("TC UDP session is closed")
	}
	binding, loaded := s.bindings[destination]
	if !loaded {
		return E.New("TC UDP assignment binding is missing")
	}
	if binding.tcReturn.IsValid() {
		return nil
	}
	handle, err := backend.AcquireReturnRoute(commonEBPF.ProtocolUDP, client, destination)
	if err != nil {
		return err
	}
	binding.tcReturn = handle
	s.bindings[destination] = binding
	return nil
}

func (s *udpClientState) retainTCReplyReturn(backend *commonEBPF.TCBackend, destination netip.AddrPort) error {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return E.New("TC UDP session is closed")
	}
	binding, loaded := s.bindings[destination]
	if !loaded {
		return E.New("TC UDP reply binding is missing")
	}
	if binding.tcReturn.IsValid() {
		return nil
	}
	for originalDestination, original := range s.bindings {
		if originalDestination.Addr().Is4() != destination.Addr().Is4() || !original.tcReturn.IsValid() {
			continue
		}
		handle, err := backend.AcquireReplyRoute(original.tcReturn, destination)
		if err != nil {
			return err
		}
		binding.tcReturn = handle
		s.bindings[destination] = binding
		return nil
	}
	return E.New("TC UDP reply has no retained return route")
}

func (s *udpClientState) isCgroupDataPlane() bool {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.cgroupDataPlane
}

func sourcePacketInfo(address netip.Addr) []byte {
	if address.Is4() {
		return (&ipv4.ControlMessage{Src: net.IP(address.AsSlice())}).Marshal()
	}
	return (&ipv6.ControlMessage{Src: net.IP(address.AsSlice())}).Marshal()
}

func (s *udpClientState) redirectBinding(destination netip.AddrPort) (udpRedirectBinding, bool) {
	s.access.RLock()
	binding, loaded := s.bindings[destination]
	s.access.RUnlock()
	return binding, loaded
}

func (s *udpClientState) hasAddressFamily(ipv4 bool) bool {
	s.access.RLock()
	defer s.access.RUnlock()
	if s.replyAliasCount >= udpReplyAliasLimit {
		return false
	}
	for destination := range s.bindings {
		if destination.Addr().Is4() == ipv4 {
			return true
		}
	}
	return false
}

func (s *udpClientState) sourceMACAddress() net.HardwareAddr {
	s.access.RLock()
	defer s.access.RUnlock()
	return append(net.HardwareAddr(nil), s.sourceMAC...)
}

func (s *udpClientState) processSocketCookie() uint64 {
	s.access.RLock()
	defer s.access.RUnlock()
	return s.socketCookie
}
