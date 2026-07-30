//go:build with_ebpf && (linux || android)

package ebpf

import (
	"net/netip"
	"sync"
)

type udpClientTable struct {
	access             sync.RWMutex
	clients            map[netip.AddrPort]*udpClientState
	redirectAccess     sync.Mutex
	redirectReferences map[netip.Addr]uint32
}

type udpClientState struct {
	access    sync.RWMutex
	connected bool
	uid       uint32
	bindings  map[netip.AddrPort]udpRedirectBinding
}

func (t *udpClientTable) setUID(client netip.AddrPort, uid uint32) {
	clientState := t.loadOrCreate(client)
	clientState.access.Lock()
	clientState.uid = uid
	clientState.access.Unlock()
}

type udpRedirectBinding struct {
	address   netip.Addr
	connected bool
}

func (t *udpClientTable) load(client netip.AddrPort) (*udpClientState, bool) {
	t.access.RLock()
	clientState, loaded := t.clients[client]
	t.access.RUnlock()
	return clientState, loaded
}

func (t *udpClientTable) loadOrCreate(client netip.AddrPort) *udpClientState {
	if clientState, loaded := t.load(client); loaded {
		return clientState
	}
	t.access.Lock()
	defer t.access.Unlock()
	return t.loadOrCreateLocked(client)
}

func (t *udpClientTable) loadOrCreateLocked(client netip.AddrPort) *udpClientState {
	if clientState, loaded := t.clients[client]; loaded {
		return clientState
	}
	if t.clients == nil {
		t.clients = make(map[netip.AddrPort]*udpClientState)
	}
	clientState := &udpClientState{bindings: make(map[netip.AddrPort]udpRedirectBinding)}
	t.clients[client] = clientState
	return clientState
}

func (t *udpClientTable) setBinding(
	client netip.AddrPort,
	destination netip.AddrPort,
	redirectAddress netip.Addr,
	connected bool,
) []netip.Addr {
	t.access.RLock()
	clientState, loaded := t.clients[client]
	if loaded {
		released := t.setClientBinding(clientState, destination, redirectAddress, connected)
		t.access.RUnlock()
		return released
	}
	t.access.RUnlock()

	t.access.Lock()
	clientState = t.loadOrCreateLocked(client)
	released := t.setClientBinding(clientState, destination, redirectAddress, connected)
	t.access.Unlock()
	return released
}

func (t *udpClientTable) setClientBinding(
	clientState *udpClientState,
	destination netip.AddrPort,
	redirectAddress netip.Addr,
	connected bool,
) []netip.Addr {
	clientState.access.RLock()
	current, loaded := clientState.bindings[destination]
	clientState.access.RUnlock()
	if loaded && current.address == redirectAddress && current.connected == connected {
		return nil
	}

	clientState.access.Lock()
	defer clientState.access.Unlock()
	current, loaded = clientState.bindings[destination]
	if loaded && current.address == redirectAddress && current.connected == connected {
		return nil
	}
	clientState.bindings[destination] = udpRedirectBinding{
		address:   redirectAddress,
		connected: connected,
	}

	t.redirectAccess.Lock()
	defer t.redirectAccess.Unlock()
	if !connected {
		t.retainRedirectLocked(redirectAddress)
	}
	if loaded && !current.connected && t.releaseRedirectLocked(current.address) {
		return []netip.Addr{current.address}
	}
	return nil
}

func (t *udpClientTable) delete(client netip.AddrPort, expected *udpClientState) []netip.Addr {
	t.access.Lock()
	defer t.access.Unlock()
	if t.clients[client] != expected {
		return nil
	}
	delete(t.clients, client)

	expected.access.Lock()
	defer expected.access.Unlock()
	t.redirectAccess.Lock()
	defer t.redirectAccess.Unlock()
	var released []netip.Addr
	for _, binding := range expected.bindings {
		if !binding.connected && t.releaseRedirectLocked(binding.address) {
			released = append(released, binding.address)
		}
	}
	clear(expected.bindings)
	return released
}

func (t *udpClientTable) retainRedirectLocked(redirectAddress netip.Addr) {
	if t.redirectReferences == nil {
		t.redirectReferences = make(map[netip.Addr]uint32)
	}
	t.redirectReferences[redirectAddress]++
}

func (t *udpClientTable) releaseRedirectLocked(redirectAddress netip.Addr) bool {
	references := t.redirectReferences[redirectAddress]
	if references > 1 {
		t.redirectReferences[redirectAddress] = references - 1
		return false
	}
	if references == 1 {
		delete(t.redirectReferences, redirectAddress)
		return true
	}
	return false
}

func (s *udpClientState) redirectAddress(destination netip.AddrPort) (netip.Addr, bool) {
	s.access.RLock()
	binding, loaded := s.bindings[destination]
	s.access.RUnlock()
	return binding.address, loaded
}

func (s *udpClientState) setConnected(connected bool) {
	s.access.Lock()
	s.connected = connected
	s.access.Unlock()
}

func (s *udpClientState) isConnected() bool {
	s.access.RLock()
	connected := s.connected
	s.access.RUnlock()
	return connected
}

func (s *udpClientState) sourceUID() uint32 {
	s.access.RLock()
	uid := s.uid
	s.access.RUnlock()
	return uid
}
