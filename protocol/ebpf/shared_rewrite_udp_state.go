//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	ECommon "github.com/CHIZI-0618/sing-ebpf"
)

type sharedUDPClientTable struct {
	clientShards       [sharedUDPClientShardCount]sharedUDPClientShard
	redirectAccess     sync.Mutex
	redirectReferences map[sharedUDPRedirectReference]uint32
	redirectSessions   map[sharedUDPRedirectReference]udpSessionKey
}

const sharedUDPClientShardCount = 16

type sharedUDPClientShard struct {
	access  sync.RWMutex
	clients map[udpSessionKey]*sharedUDPClientState
}

type sharedUDPClientState struct {
	access               sync.RWMutex
	connectedBinding     atomic.Pointer[sharedUDPRedirectBinding]
	connected            bool
	connectedDestination netip.AddrPort
	sourceMAC            net.HardwareAddr
	bindings             map[netip.AddrPort]sharedUDPRedirectBinding
	originals            map[netip.Addr]sharedUDPOriginalDestination
	replyAliasCount      uint16
}

type sharedUDPRedirectBinding struct {
	address    netip.Addr
	packetInfo []byte
	connected  bool
	reference  sharedUDPRedirectReference
	sharedFlow *ECommon.SharedPacketRewriteFlowHandle
	replyAlias bool
}

type sharedUDPRedirectReference struct {
	client  netip.AddrPort
	address netip.Addr
}

type sharedUDPRedirectRelease struct {
	reference  sharedUDPRedirectReference
	sharedFlow *ECommon.SharedPacketRewriteFlowHandle
}

type sharedUDPOriginalDestination struct {
	original   ECommon.OriginalDestination
	sharedFlow *ECommon.SharedPacketRewriteFlowHandle
	replyAlias bool
}

const sharedUDPReplyAliasLimit = 64

// count reports the number of tracked shared packet-rewrite UDP clients,
// for diagnostics -- udpClientTable.count()'s counterpart for the local/TC
// client table, which Diagnostics' own UDPSessionCount previously reported
// alone: a shared.data_plane: packet_rewrite inbound with no local role at
// all keeps its live UDP clients exclusively in this table, so
// UDPSessionCount always read 0 for it regardless of how many clients were
// actually active. Like udpClientTable.count(), this locks each shard in
// turn rather than all at once, so it is a point-in-time estimate under
// concurrent traffic, not a value consistent with any single instant.
func (t *sharedUDPClientTable) count() int {
	total := 0
	for index := range t.clientShards {
		shard := &t.clientShards[index]
		shard.access.RLock()
		total += len(shard.clients)
		shard.access.RUnlock()
	}
	return total
}

func (t *sharedUDPClientTable) load(key udpSessionKey) (*sharedUDPClientState, bool) {
	shard := t.clientShard(key)
	shard.access.RLock()
	clientState, loaded := shard.clients[key]
	shard.access.RUnlock()
	return clientState, loaded
}

func (t *sharedUDPClientTable) loadOrCreate(key udpSessionKey) *sharedUDPClientState {
	if clientState, loaded := t.load(key); loaded {
		return clientState
	}
	shard := t.clientShard(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	return shard.loadOrCreateLocked(key)
}

func (s *sharedUDPClientShard) loadOrCreateLocked(key udpSessionKey) *sharedUDPClientState {
	if clientState, loaded := s.clients[key]; loaded {
		return clientState
	}
	if s.clients == nil {
		s.clients = make(map[udpSessionKey]*sharedUDPClientState)
	}
	clientState := &sharedUDPClientState{
		bindings:  make(map[netip.AddrPort]sharedUDPRedirectBinding),
		originals: make(map[netip.Addr]sharedUDPOriginalDestination),
	}
	s.clients[key] = clientState
	return clientState
}

func (t *sharedUDPClientTable) clientShard(key udpSessionKey) *sharedUDPClientShard {
	return &t.clientShards[shardIndexForAddrPort(key.Source, sharedUDPClientShardCount)]
}

func (t *sharedUDPClientTable) cachedPacketState(
	client netip.AddrPort,
	redirectAddress netip.Addr,
) (udpSessionKey, sharedUDPOriginalDestination, bool, bool) {
	reference := sharedUDPRedirectReference{client: client, address: redirectAddress}
	t.redirectAccess.Lock()
	key, loaded := t.redirectSessions[reference]
	t.redirectAccess.Unlock()
	if !loaded {
		return udpSessionKey{}, sharedUDPOriginalDestination{}, false, false
	}
	clientState, loaded := t.load(key)
	if !loaded {
		return udpSessionKey{}, sharedUDPOriginalDestination{}, false, false
	}
	clientState.access.RLock()
	original, loaded := clientState.originals[redirectAddress]
	if !loaded {
		clientState.access.RUnlock()
		return udpSessionKey{}, sharedUDPOriginalDestination{}, false, false
	}
	binding, bindingLoaded := clientState.bindings[original.original.Destination]
	bindingReady := bindingLoaded &&
		binding.address == redirectAddress &&
		binding.connected == original.original.ConnectedUDP
	clientState.access.RUnlock()
	return key, original, bindingReady, true
}

func (t *sharedUDPClientTable) setBinding(
	key udpSessionKey,
	destination netip.AddrPort,
	redirectAddress netip.Addr,
	connected bool,
) []netip.Addr {
	releases, _ := t.setBindingState(
		key,
		redirectAddress,
		sharedUDPRedirectReference{client: key.Source, address: redirectAddress},
		sharedUDPOriginalDestination{
			original: ECommon.OriginalDestination{
				Destination:  destination,
				ConnectedUDP: connected,
			},
		},
	)
	addresses := make([]netip.Addr, 0, len(releases))
	for _, release := range releases {
		addresses = append(addresses, release.reference.address)
	}
	return addresses
}

func (t *sharedUDPClientTable) setSharedBinding(
	key udpSessionKey,
	original ECommon.OriginalDestination,
	redirectAddress netip.Addr,
	flow *ECommon.SharedPacketRewriteFlowHandle,
) ([]sharedUDPRedirectRelease, bool) {
	return t.setBindingState(
		key,
		redirectAddress,
		sharedUDPRedirectReference{client: key.Source, address: redirectAddress},
		sharedUDPOriginalDestination{
			original:   original,
			sharedFlow: flow,
		},
	)
}

func (t *sharedUDPClientTable) setSharedReplyBinding(
	key udpSessionKey,
	expectedState *sharedUDPClientState,
	original ECommon.OriginalDestination,
	redirectAddress netip.Addr,
	flow *ECommon.SharedPacketRewriteFlowHandle,
) ([]sharedUDPRedirectRelease, bool) {
	return t.setExistingBindingState(
		key,
		expectedState,
		redirectAddress,
		sharedUDPRedirectReference{client: key.Source, address: redirectAddress},
		sharedUDPOriginalDestination{original: original, sharedFlow: flow, replyAlias: true},
	)
}

func (t *sharedUDPClientTable) setExistingBindingState(
	key udpSessionKey,
	expectedState *sharedUDPClientState,
	redirectAddress netip.Addr,
	reference sharedUDPRedirectReference,
	original sharedUDPOriginalDestination,
) ([]sharedUDPRedirectRelease, bool) {
	shard := t.clientShard(key)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[key] != expectedState {
		return nil, false
	}
	return t.setClientBinding(key, expectedState, redirectAddress, reference, original)
}

func (t *sharedUDPClientTable) setBindingState(
	key udpSessionKey,
	redirectAddress netip.Addr,
	reference sharedUDPRedirectReference,
	original sharedUDPOriginalDestination,
) ([]sharedUDPRedirectRelease, bool) {
	shard := t.clientShard(key)
	shard.access.RLock()
	clientState, loaded := shard.clients[key]
	if loaded {
		released, installed := t.setClientBinding(key, clientState, redirectAddress, reference, original)
		shard.access.RUnlock()
		return released, installed
	}
	shard.access.RUnlock()

	shard.access.Lock()
	clientState = shard.loadOrCreateLocked(key)
	released, installed := t.setClientBinding(key, clientState, redirectAddress, reference, original)
	shard.access.Unlock()
	return released, installed
}

func (t *sharedUDPClientTable) setClientBinding(
	key udpSessionKey,
	clientState *sharedUDPClientState,
	redirectAddress netip.Addr,
	reference sharedUDPRedirectReference,
	original sharedUDPOriginalDestination,
) ([]sharedUDPRedirectRelease, bool) {
	destination := original.original.Destination
	connected := original.original.ConnectedUDP
	clientState.access.RLock()
	current, loaded := clientState.bindings[destination]
	clientState.access.RUnlock()
	if loaded && current.address == redirectAddress && current.connected == connected &&
		current.replyAlias == original.replyAlias {
		return nil, false
	}

	clientState.access.Lock()
	defer clientState.access.Unlock()
	current, loaded = clientState.bindings[destination]
	if loaded && current.address == redirectAddress && current.connected == connected &&
		current.replyAlias == original.replyAlias {
		return nil, false
	}
	if original.replyAlias && (!loaded || !current.replyAlias) && clientState.replyAliasCount >= sharedUDPReplyAliasLimit {
		return nil, false
	}
	clientState.originals[redirectAddress] = original
	if len(original.original.SourceMAC) != 0 {
		clientState.sourceMAC = append(clientState.sourceMAC[:0], original.original.SourceMAC...)
	}
	binding := sharedUDPRedirectBinding{
		address:    redirectAddress,
		packetInfo: sourcePacketInfo(redirectAddress),
		connected:  connected,
		reference:  reference,
		sharedFlow: original.sharedFlow,
		replyAlias: original.replyAlias,
	}
	clientState.bindings[destination] = binding
	if original.replyAlias && (!loaded || !current.replyAlias) {
		clientState.replyAliasCount++
	} else if !original.replyAlias && loaded && current.replyAlias {
		clientState.replyAliasCount--
	}
	if clientState.connected && clientState.connectedDestination == destination {
		connectedBinding := binding
		clientState.connectedBinding.Store(&connectedBinding)
	}
	oldAddressUnused := false
	if loaded && current.address != redirectAddress {
		oldAddressUnused = clientState.deleteUnusedOriginalLocked(current.address)
	}

	t.redirectAccess.Lock()
	defer t.redirectAccess.Unlock()
	if t.redirectSessions == nil {
		t.redirectSessions = make(map[sharedUDPRedirectReference]udpSessionKey)
	}
	t.redirectSessions[reference] = key
	if oldAddressUnused {
		oldReference := sharedUDPRedirectReference{client: key.Source, address: current.address}
		if t.redirectSessions[oldReference] == key {
			delete(t.redirectSessions, oldReference)
		}
	}
	if !connected {
		t.retainRedirectLocked(reference)
	}
	if loaded && !current.connected && t.releaseRedirectLocked(current.reference) {
		return []sharedUDPRedirectRelease{{
			reference:  current.reference,
			sharedFlow: current.sharedFlow,
		}}, true
	}
	return nil, true
}

func (s *sharedUDPClientState) deleteUnusedOriginalLocked(address netip.Addr) bool {
	for _, binding := range s.bindings {
		if binding.address == address {
			return false
		}
	}
	delete(s.originals, address)
	return true
}

func (t *sharedUDPClientTable) deleteShared(key udpSessionKey, expectedState *sharedUDPClientState) []sharedUDPRedirectRelease {
	return t.deleteClient(key, expectedState)
}

func (t *sharedUDPClientTable) deleteClient(key udpSessionKey, expectedState *sharedUDPClientState) []sharedUDPRedirectRelease {
	shard := t.clientShard(key)
	shard.access.Lock()
	defer shard.access.Unlock()
	if shard.clients[key] != expectedState {
		return nil
	}
	delete(shard.clients, key)

	expectedState.access.Lock()
	defer expectedState.access.Unlock()
	t.redirectAccess.Lock()
	defer t.redirectAccess.Unlock()
	for address := range expectedState.originals {
		reference := sharedUDPRedirectReference{client: key.Source, address: address}
		if t.redirectSessions[reference] == key {
			delete(t.redirectSessions, reference)
		}
	}
	var released []sharedUDPRedirectRelease
	for _, binding := range expectedState.bindings {
		if !binding.connected && t.releaseRedirectLocked(binding.reference) {
			released = append(released, sharedUDPRedirectRelease{
				reference:  binding.reference,
				sharedFlow: binding.sharedFlow,
			})
		}
	}
	clear(expectedState.bindings)
	clear(expectedState.originals)
	expectedState.replyAliasCount = 0
	expectedState.connectedBinding.Store(nil)
	return released
}

func (t *sharedUDPClientTable) retainRedirectLocked(reference sharedUDPRedirectReference) {
	if t.redirectReferences == nil {
		t.redirectReferences = make(map[sharedUDPRedirectReference]uint32)
	}
	t.redirectReferences[reference]++
}

func (t *sharedUDPClientTable) releaseRedirectLocked(reference sharedUDPRedirectReference) bool {
	references := t.redirectReferences[reference]
	if references > 1 {
		t.redirectReferences[reference] = references - 1
		return false
	}
	if references == 1 {
		delete(t.redirectReferences, reference)
		return true
	}
	return false
}

func (s *sharedUDPClientState) redirectBinding(destination netip.AddrPort) (sharedUDPRedirectBinding, bool) {
	if binding := s.connectedBinding.Load(); binding != nil {
		return *binding, true
	}
	s.access.RLock()
	if s.connected {
		destination = s.connectedDestination
	}
	binding, loaded := s.bindings[destination]
	s.access.RUnlock()
	return binding, loaded
}

func (s *sharedUDPClientState) replyTemplate(destination netip.AddrPort, shared bool) (sharedUDPRedirectBinding, bool) {
	s.access.RLock()
	defer s.access.RUnlock()
	if s.replyAliasCount >= sharedUDPReplyAliasLimit {
		return sharedUDPRedirectBinding{}, false
	}
	for _, binding := range s.bindings {
		if binding.address.Is4() == destination.Addr().Is4() && (!shared || binding.sharedFlow != nil) {
			return binding, true
		}
	}
	return sharedUDPRedirectBinding{}, false
}

func (s *sharedUDPClientState) sourceMACAddress() net.HardwareAddr {
	s.access.RLock()
	defer s.access.RUnlock()
	return append(net.HardwareAddr(nil), s.sourceMAC...)
}
