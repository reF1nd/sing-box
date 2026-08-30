//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net"
	"net/netip"
	"sync"
	"sync/atomic"

	ECommon "github.com/sagernet/sing-box/common/ebpf"
)

type sharedUDPClientTable struct {
	clientShards       [sharedUDPClientShardCount]sharedUDPClientShard
	redirectAccess     sync.Mutex
	redirectReferences map[sharedUDPRedirectReference]uint32
}

const sharedUDPClientShardCount = 16

type sharedUDPClientShard struct {
	access  sync.RWMutex
	clients map[netip.AddrPort]*sharedUDPClientState
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
	sharedFlow *ECommon.SharedNetworkFlowHandle
	replyAlias bool
}

type sharedUDPRedirectReference struct {
	client  netip.AddrPort
	address netip.Addr
}

type sharedUDPRedirectRelease struct {
	reference  sharedUDPRedirectReference
	sharedFlow *ECommon.SharedNetworkFlowHandle
}

type sharedUDPOriginalDestination struct {
	original   ECommon.OriginalDestination
	sharedFlow *ECommon.SharedNetworkFlowHandle
	replyAlias bool
}

const sharedUDPReplyAliasLimit = 64

func (t *sharedUDPClientTable) load(client netip.AddrPort) (*sharedUDPClientState, bool) {
	shard := t.clientShard(client)
	shard.access.RLock()
	clientState, loaded := shard.clients[client]
	shard.access.RUnlock()
	return clientState, loaded
}

func (t *sharedUDPClientTable) current(client netip.AddrPort, expectedState *sharedUDPClientState) bool {
	clientState, loaded := t.load(client)
	return loaded && clientState == expectedState
}

func (t *sharedUDPClientTable) loadOrCreate(client netip.AddrPort) *sharedUDPClientState {
	if clientState, loaded := t.load(client); loaded {
		return clientState
	}
	shard := t.clientShard(client)
	shard.access.Lock()
	defer shard.access.Unlock()
	return shard.loadOrCreateLocked(client)
}

func (s *sharedUDPClientShard) loadOrCreateLocked(client netip.AddrPort) *sharedUDPClientState {
	if clientState, loaded := s.clients[client]; loaded {
		return clientState
	}
	if s.clients == nil {
		s.clients = make(map[netip.AddrPort]*sharedUDPClientState)
	}
	clientState := &sharedUDPClientState{
		bindings:  make(map[netip.AddrPort]sharedUDPRedirectBinding),
		originals: make(map[netip.Addr]sharedUDPOriginalDestination),
	}
	s.clients[client] = clientState
	return clientState
}

func (t *sharedUDPClientTable) clientShard(client netip.AddrPort) *sharedUDPClientShard {
	port := client.Port()
	index := (port ^ port>>8) & (sharedUDPClientShardCount - 1)
	return &t.clientShards[index]
}

func (t *sharedUDPClientTable) cachedOriginal(client netip.AddrPort, redirectAddress netip.Addr) (sharedUDPOriginalDestination, bool) {
	original, _, loaded := t.cachedPacketState(client, redirectAddress)
	return original, loaded
}

func (t *sharedUDPClientTable) cachedPacketState(
	client netip.AddrPort,
	redirectAddress netip.Addr,
) (sharedUDPOriginalDestination, bool, bool) {
	clientState, loaded := t.load(client)
	if !loaded {
		return sharedUDPOriginalDestination{}, false, false
	}
	clientState.access.RLock()
	original, loaded := clientState.originals[redirectAddress]
	if !loaded {
		clientState.access.RUnlock()
		return sharedUDPOriginalDestination{}, false, false
	}
	binding, bindingLoaded := clientState.bindings[original.original.Destination]
	bindingReady := bindingLoaded &&
		binding.address == redirectAddress &&
		binding.connected == original.original.ConnectedUDP
	clientState.access.RUnlock()
	return original, bindingReady, true
}

func (t *sharedUDPClientTable) setBinding(
	client netip.AddrPort,
	destination netip.AddrPort,
	redirectAddress netip.Addr,
	connected bool,
) []netip.Addr {
	releases, _ := t.setBindingState(
		client,
		redirectAddress,
		sharedUDPRedirectReference{address: redirectAddress},
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
	client netip.AddrPort,
	original ECommon.OriginalDestination,
	redirectAddress netip.Addr,
	flow *ECommon.SharedNetworkFlowHandle,
) ([]sharedUDPRedirectRelease, bool) {
	return t.setBindingState(
		client,
		redirectAddress,
		sharedUDPRedirectReference{client: client, address: redirectAddress},
		sharedUDPOriginalDestination{
			original:   original,
			sharedFlow: flow,
		},
	)
}

func (t *sharedUDPClientTable) setReplyBinding(
	client netip.AddrPort,
	expectedState *sharedUDPClientState,
	destination netip.AddrPort,
	redirectAddress netip.Addr,
) ([]netip.Addr, bool) {
	releases, installed := t.setExistingBindingState(
		client,
		expectedState,
		redirectAddress,
		sharedUDPRedirectReference{address: redirectAddress},
		sharedUDPOriginalDestination{
			original:   ECommon.OriginalDestination{Destination: destination},
			replyAlias: true,
		},
	)
	addresses := make([]netip.Addr, 0, len(releases))
	for _, release := range releases {
		addresses = append(addresses, release.reference.address)
	}
	return addresses, installed
}

func (t *sharedUDPClientTable) setSharedReplyBinding(
	client netip.AddrPort,
	expectedState *sharedUDPClientState,
	original ECommon.OriginalDestination,
	redirectAddress netip.Addr,
	flow *ECommon.SharedNetworkFlowHandle,
) ([]sharedUDPRedirectRelease, bool) {
	return t.setExistingBindingState(
		client,
		expectedState,
		redirectAddress,
		sharedUDPRedirectReference{client: client, address: redirectAddress},
		sharedUDPOriginalDestination{original: original, sharedFlow: flow, replyAlias: true},
	)
}

func (t *sharedUDPClientTable) setExistingBindingState(
	client netip.AddrPort,
	expectedState *sharedUDPClientState,
	redirectAddress netip.Addr,
	reference sharedUDPRedirectReference,
	original sharedUDPOriginalDestination,
) ([]sharedUDPRedirectRelease, bool) {
	shard := t.clientShard(client)
	shard.access.RLock()
	defer shard.access.RUnlock()
	if shard.clients[client] != expectedState {
		return nil, false
	}
	return t.setClientBinding(expectedState, redirectAddress, reference, original)
}

func (t *sharedUDPClientTable) setBindingState(
	client netip.AddrPort,
	redirectAddress netip.Addr,
	reference sharedUDPRedirectReference,
	original sharedUDPOriginalDestination,
) ([]sharedUDPRedirectRelease, bool) {
	shard := t.clientShard(client)
	shard.access.RLock()
	clientState, loaded := shard.clients[client]
	if loaded {
		released, installed := t.setClientBinding(clientState, redirectAddress, reference, original)
		shard.access.RUnlock()
		return released, installed
	}
	shard.access.RUnlock()

	shard.access.Lock()
	clientState = shard.loadOrCreateLocked(client)
	released, installed := t.setClientBinding(clientState, redirectAddress, reference, original)
	shard.access.Unlock()
	return released, installed
}

func (t *sharedUDPClientTable) setClientBinding(
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
	if loaded && current.address != redirectAddress {
		clientState.deleteUnusedOriginalLocked(current.address)
	}

	t.redirectAccess.Lock()
	defer t.redirectAccess.Unlock()
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

func (s *sharedUDPClientState) deleteUnusedOriginalLocked(address netip.Addr) {
	for _, binding := range s.bindings {
		if binding.address == address {
			return
		}
	}
	delete(s.originals, address)
}

func (t *sharedUDPClientTable) delete(client netip.AddrPort, expectedState *sharedUDPClientState) []netip.Addr {
	releases := t.deleteClient(client, expectedState)
	addresses := make([]netip.Addr, 0, len(releases))
	for _, release := range releases {
		addresses = append(addresses, release.reference.address)
	}
	return addresses
}

func (t *sharedUDPClientTable) deleteShared(client netip.AddrPort, expectedState *sharedUDPClientState) []sharedUDPRedirectRelease {
	return t.deleteClient(client, expectedState)
}

func (t *sharedUDPClientTable) deleteClient(client netip.AddrPort, expectedState *sharedUDPClientState) []sharedUDPRedirectRelease {
	shard := t.clientShard(client)
	shard.access.Lock()
	defer shard.access.Unlock()
	if shard.clients[client] != expectedState {
		return nil
	}
	delete(shard.clients, client)

	expectedState.access.Lock()
	defer expectedState.access.Unlock()
	t.redirectAccess.Lock()
	defer t.redirectAccess.Unlock()
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

func (s *sharedUDPClientState) setConnected(connected bool, destination netip.AddrPort) {
	s.access.Lock()
	s.connected = connected
	if connected {
		s.connectedDestination = destination
		if binding, loaded := s.bindings[destination]; loaded {
			connectedBinding := binding
			s.connectedBinding.Store(&connectedBinding)
		} else {
			s.connectedBinding.Store(nil)
		}
	} else {
		s.connectedDestination = netip.AddrPort{}
		s.connectedBinding.Store(nil)
	}
	s.access.Unlock()
}

func (s *sharedUDPClientState) isConnected() bool {
	s.access.RLock()
	connected := s.connected
	s.access.RUnlock()
	return connected
}
