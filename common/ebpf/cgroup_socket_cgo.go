//go:build with_ebpf && (linux || android) && cgo

package ebpf

import (
	"errors"
	"net/netip"
	"syscall"
	"unsafe"

	"github.com/sagernet/sing/common/control"
	E "github.com/sagernet/sing/common/exceptions"

	"golang.org/x/sys/unix"
)

const (
	mapLookupAndDeleteUnknown int32 = iota
	mapLookupAndDeleteSupported
	mapLookupAndDeleteUnsupported
)

func (b *CgroupBackend) SocketProtectFunc() control.Func {
	if b == nil {
		return nil
	}
	return func(network string, address string, rawConn syscall.RawConn) error {
		b.access.RLock()
		if b.runtime == nil {
			b.access.RUnlock()
			return errBackendClosed
		}
		if b.runtime.self_bypass_tgid {
			b.access.RUnlock()
			return nil
		}
		b.access.RUnlock()
		return control.Raw(rawConn, func(fd uintptr) error {
			cookie, err := readSocketCookie(fd)
			if err != nil {
				return E.Cause(err, "read socket cookie")
			}
			b.access.RLock()
			if b.runtime == nil {
				b.access.RUnlock()
				return errBackendClosed
			}
			if b.runtime.self_bypass_tgid {
				b.access.RUnlock()
				return nil
			}
			if b.socketBypassMapFD >= 0 {
				err = registerSocketCookie(b.socketBypassMapFD, cookie)
				b.access.RUnlock()
				return err
			}
			b.access.RUnlock()

			b.access.Lock()
			defer b.access.Unlock()
			if b.runtime == nil {
				return errBackendClosed
			}
			if b.runtime.self_bypass_tgid {
				return nil
			}
			if b.socketBypassMapFD >= 0 {
				return registerSocketCookie(b.socketBypassMapFD, cookie)
			}
			if b.pendingSocketCookies == nil {
				b.pendingSocketCookies = make(map[uint64]struct{})
			}
			b.pendingSocketCookies[cookie] = struct{}{}
			return nil
		})
	}
}

func registerSocketCookie(mapFD int, cookie uint64) error {
	value := uint8(1)
	if err := updateMap(mapFD, unsafe.Pointer(&cookie), unsafe.Pointer(&value)); err != nil {
		return E.Cause(err, "register eBPF bypass socket")
	}
	return nil
}

func (b *CgroupBackend) LookupOriginal(protocol uint8, listenerDestination netip.AddrPort) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, listenerDestination, false)
}

func (b *CgroupBackend) TakeOriginal(protocol uint8, listenerDestination netip.AddrPort) (OriginalDestination, error) {
	return b.lookupOriginal(protocol, listenerDestination, true)
}

func (b *CgroupBackend) lookupOriginal(
	protocol uint8,
	listenerDestination netip.AddrPort,
	deleteAfterLookup bool,
) (OriginalDestination, error) {
	if b == nil {
		return OriginalDestination{}, errBackendClosed
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return OriginalDestination{}, errBackendClosed
	}
	key, err := makeListenerLookupKey(protocol, listenerDestination)
	if err != nil {
		return OriginalDestination{}, err
	}
	var original originalDestinationValue
	redirectMap, err := b.redirectMap(protocol)
	if err != nil {
		return OriginalDestination{}, err
	}
	if deleteAfterLookup {
		err = b.takeMapElement(redirectMap, unsafe.Pointer(&key), unsafe.Pointer(&original))
	} else {
		err = lookupMap(redirectMap, unsafe.Pointer(&key), unsafe.Pointer(&original))
	}
	if err != nil {
		return OriginalDestination{}, E.Cause(err, "lookup original destination")
	}
	var address netip.Addr
	switch original.Family {
	case addressFamilyIPv4:
		address = netip.AddrFrom4([4]byte(original.Addr[:4]))
	case addressFamilyIPv6:
		address = netip.AddrFrom16(original.Addr)
	default:
		return OriginalDestination{}, E.New("invalid original destination family: ", original.Family)
	}
	return OriginalDestination{
		Destination:  netip.AddrPortFrom(address.Unmap(), original.Port),
		ConnectedUDP: original.Flags&1 != 0,
	}, nil
}

func (b *CgroupBackend) takeMapElement(mapFD int, key unsafe.Pointer, value unsafe.Pointer) error {
	if b.lookupAndDeleteMode.Load() != mapLookupAndDeleteUnsupported {
		err := lookupAndDeleteMap(mapFD, key, value)
		if err == nil || errors.Is(err, unix.ENOENT) {
			b.lookupAndDeleteMode.Store(mapLookupAndDeleteSupported)
			return err
		}
		if !mapLookupAndDeleteUnavailable(err) {
			return err
		}
		b.lookupAndDeleteMode.Store(mapLookupAndDeleteUnsupported)
	}
	if err := lookupMap(mapFD, key, value); err != nil {
		return err
	}
	err := deleteMap(mapFD, key)
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	return err
}

func mapLookupAndDeleteUnavailable(err error) bool {
	return errors.Is(err, unix.ENOSYS) ||
		errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.EOPNOTSUPP) ||
		errors.Is(err, linuxErrnoNotSupported)
}

func (b *CgroupBackend) DeleteRedirect(protocol uint8, listenerDestination netip.AddrPort) error {
	if b == nil {
		return errBackendClosed
	}
	key, err := makeListenerLookupKey(protocol, listenerDestination)
	if err != nil {
		return err
	}
	b.access.RLock()
	defer b.access.RUnlock()
	if b.runtime == nil {
		return errBackendClosed
	}
	redirectMap, err := b.redirectMap(protocol)
	if err != nil {
		return err
	}
	if protocol == ProtocolUDP && b.udpFlowMapFD >= 0 {
		var original originalDestinationValue
		lookupErr := lookupMap(redirectMap, unsafe.Pointer(&key), unsafe.Pointer(&original))
		if lookupErr == nil && original.SocketCookie != 0 {
			flowKey := makeUDPFlowKey(original)
			flowErr := deleteMap(b.udpFlowMapFD, unsafe.Pointer(&flowKey))
			if flowErr != nil && !errors.Is(flowErr, unix.ENOENT) {
				return E.Cause(flowErr, "delete UDP flow cache")
			}
		} else if lookupErr != nil && !errors.Is(lookupErr, unix.ENOENT) {
			return E.Cause(lookupErr, "lookup UDP flow cache key")
		}
	}
	err = deleteMap(redirectMap, unsafe.Pointer(&key))
	if errors.Is(err, unix.ENOENT) {
		return nil
	}
	if err != nil {
		return E.Cause(err, "delete redirect mapping")
	}
	return nil
}

func (b *CgroupBackend) redirectMap(protocol uint8) (int, error) {
	switch protocol {
	case ProtocolTCP:
		return b.tcpRedirectMapFD, nil
	case ProtocolUDP:
		return b.udpRedirectMapFD, nil
	default:
		return -1, E.New("unsupported eBPF redirect protocol: ", protocol)
	}
}
