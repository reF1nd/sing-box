//go:build with_randomaddr

package outbound

import (
	"context"
	"math/big"
	"math/rand"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

var _ adapter.Outbound = (*RandomAddr)(nil)

type RandomAddr struct {
	myOutboundAdapter
	ctx             context.Context
	dialer          N.Dialer
	randomAddresses []randomAddress
	ignoreFqdn      bool
	deleteFqdn      bool
	udp             bool
}

func NewRandomAddr(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.RandomAddrOutboundOptions) (adapter.Outbound, error) {
	if len(options.Addresses) == 0 {
		return nil, E.New("no addresses")
	}
	outboundDialer, err := dialer.New(router, options.DialerOptions)
	if err != nil {
		return nil, err
	}
	randomAddresses := make([]randomAddress, 0, len(options.Addresses))
	for _, address := range options.Addresses {
		randomAddress, err := newRandomAddress(address.IP, address.Port)
		if err != nil {
			return nil, E.Cause(err, address)
		}
		randomAddresses = append(randomAddresses, *randomAddress)
	}
	r := &RandomAddr{
		myOutboundAdapter: myOutboundAdapter{
			protocol:     C.TypeRandomAddr,
			router:       router,
			logger:       logger,
			tag:          tag,
			dependencies: withDialerDependency(options.DialerOptions),
		},
		ctx:             ctx,
		dialer:          outboundDialer,
		randomAddresses: randomAddresses,
		ignoreFqdn:      options.IgnoreFqdn,
		deleteFqdn:      options.DeleteFqdn,
		udp:             options.UDP,
	}
	return r, nil
}

func (r *RandomAddr) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	r.overrideDestination(ctx, &destination)
	return r.dialer.DialContext(ctx, network, destination)
}

func (r *RandomAddr) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	if r.udp {
		r.overrideDestination(ctx, &destination)
	}
	return r.dialer.ListenPacket(ctx, destination)
}

func (r *RandomAddr) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext) error {
	return NewConnection(ctx, r, conn, metadata)
}

func (r *RandomAddr) NewPacketConnection(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext) error {
	return NewPacketConnection(ctx, r, conn, metadata)
}

func (r *RandomAddr) overrideDestination(ctx context.Context, destination *M.Socksaddr) {
	if !destination.IsFqdn() || !r.ignoreFqdn {
		address := r.randomAddresses[randomRand().Intn(len(r.randomAddresses))].randomAddr(destination.Port)
		r.logger.DebugContext(ctx, "random address: ", address.String())
		destination.Addr = address.Addr()
		destination.Port = address.Port()
		if r.deleteFqdn {
			destination.Fqdn = ""
		}
	}
}

func randomRand() *rand.Rand {
	return rand.New(rand.NewSource(time.Now().UnixNano()))
}

type randomAddress struct {
	start  *netip.Addr
	end    *netip.Addr
	prefix *netip.Prefix
	port   uint16
}

func newRandomAddress(address string, port uint16) (*randomAddress, error) {
	if address == "" {
		return nil, E.New("empty ip address")
	}
	ip, err := netip.ParseAddr(address)
	if err == nil {
		return &randomAddress{start: &ip, port: port}, nil
	}
	prefix, err := netip.ParsePrefix(address)
	if err == nil {
		addr := prefix.Addr()
		if addr.Is4() && prefix.Bits() == 32 {
			return &randomAddress{start: &addr, port: port}, nil
		}
		if !addr.Is6() && prefix.Bits() == 128 {
			return &randomAddress{start: &addr, port: port}, nil
		}
		return &randomAddress{prefix: &prefix, port: port}, nil
	}
	addrs := strings.SplitN(address, "-", 2)
	if len(addrs) < 2 {
		return nil, E.New("invalid ip address")
	}
	start, err := netip.ParseAddr(addrs[0])
	if err != nil {
		return nil, E.New("invalid ip address")
	}
	end, err := netip.ParseAddr(addrs[1])
	if err != nil {
		return nil, E.New("invalid ip address")
	}
	if start.Compare(end) > 0 {
		return nil, E.New("invalid ip address")
	}
	if (start.Is4() && end.Is6()) || (start.Is6() && end.Is4()) {
		return nil, E.New("invalid ip address")
	}
	return &randomAddress{start: &start, end: &end, port: port}, nil
}

func (i *randomAddress) randomIP() netip.Addr {
	if i.prefix != nil {
		startN := big.NewInt(0).SetBytes(i.prefix.Addr().AsSlice())
		var bits int
		if i.prefix.Addr().Is4() {
			bits = 5
		} else {
			bits = 7
		}
		bt := big.NewInt(0).Exp(big.NewInt(2), big.NewInt(1<<bits-int64(i.prefix.Bits())), nil)
		bt.Sub(bt, big.NewInt(2))
		n := big.NewInt(0).Rand(randomRand(), bt)
		n.Add(n, startN)
		newAddr, _ := netip.AddrFromSlice(n.Bytes())
		return newAddr
	}
	if i.end == nil {
		return *i.start
	} else {
		startN := big.NewInt(0).SetBytes(i.start.AsSlice())
		endN := big.NewInt(0).SetBytes(i.end.AsSlice())
		addrN := big.NewInt(0).Rand(randomRand(), big.NewInt(0).Sub(endN, startN))
		addrN.Add(addrN, startN)
		addr, _ := netip.AddrFromSlice(addrN.Bytes())
		return addr
	}
}

func (i *randomAddress) randomAddr(port uint16) netip.AddrPort {
	addr := i.randomIP()
	if i.port != 0 {
		port = i.port
	}
	return netip.AddrPortFrom(addr, port)
}
