//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"errors"
	"net/netip"
	"unsafe"

	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

func (b *SharedNetworkBackend) LookupOriginal(
	protocol uint8,
	client netip.AddrPort,
	tokenDestination netip.AddrPort,
) (OriginalDestination, error) {
	original, _, err := b.lookupFlow(protocol, client, tokenDestination, false)
	return original, err
}

func (b *SharedNetworkBackend) LookupFlow(
	protocol uint8,
	client netip.AddrPort,
	tokenDestination netip.AddrPort,
) (OriginalDestination, *SharedNetworkFlowHandle, error) {
	return b.lookupFlow(protocol, client, tokenDestination, true)
}

func (b *SharedNetworkBackend) lookupFlow(
	protocol uint8,
	client netip.AddrPort,
	tokenDestination netip.AddrPort,
	retain bool,
) (OriginalDestination, *SharedNetworkFlowHandle, error) {
	if b == nil {
		return OriginalDestination{}, nil, errBackendClosed
	}
	key, err := makeSharedNetworkListenerKey(protocol, client, tokenDestination)
	if err != nil {
		return OriginalDestination{}, nil, err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, nil, errBackendClosed
	}
	if retain {
		b.flowAccess.Lock()
		defer b.flowAccess.Unlock()
	}
	var value sharedNetworkOriginalValue
	if err = lookupMap(
		int(b.runtime.listener_map_fd),
		unsafe.Pointer(&key),
		unsafe.Pointer(&value),
	); err != nil {
		return OriginalDestination{}, nil, E.Cause(err, "lookup shared-network original destination")
	}
	address, err := sharedNetworkOriginalAddress(value)
	if err != nil {
		return OriginalDestination{}, nil, err
	}
	flow := makeSharedNetworkFlowHandle(key, value)
	if retain {
		b.retainFlowLocked(flow)
	}
	return OriginalDestination{
		Destination: netip.AddrPortFrom(address, value.Port),
		SourceMAC:   sharedNetworkOriginalMAC(value),
	}, &flow, nil
}

func (b *SharedNetworkBackend) ReleaseFlow(flow *SharedNetworkFlowHandle) error {
	if b == nil || flow == nil {
		return nil
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return nil
	}
	b.flowAccess.Lock()
	defer b.flowAccess.Unlock()
	if !b.releaseFlowReferenceLocked(*flow) {
		return nil
	}
	return E.Errors(
		deleteMapIfExists(int(b.runtime.original_to_token_map_fd), unsafe.Pointer(&flow.originalKey)),
		deleteMapIfExists(int(b.runtime.listener_map_fd), unsafe.Pointer(&flow.listenerKey)),
		deleteMapIfExists(int(b.runtime.reply_map_fd), unsafe.Pointer(&flow.replyKey)),
	)
}

func (b *SharedNetworkBackend) retainFlowLocked(flow SharedNetworkFlowHandle) {
	if b.flowReferences == nil {
		b.flowReferences = make(map[SharedNetworkFlowHandle]uint32)
	}
	b.flowReferences[flow]++
}

func (b *SharedNetworkBackend) releaseFlowReferenceLocked(flow SharedNetworkFlowHandle) bool {
	references := b.flowReferences[flow]
	if references == 0 {
		return false
	}
	if references > 1 {
		b.flowReferences[flow] = references - 1
		return false
	}
	delete(b.flowReferences, flow)
	return true
}

func deleteMapIfExists(mapFD int, key unsafe.Pointer) error {
	err := deleteMap(mapFD, key)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}
