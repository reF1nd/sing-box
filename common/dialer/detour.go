package dialer

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type DirectDialer interface {
	IsEmpty() bool
}

type DetourDialer struct {
	outboundManager         adapter.OutboundManager
	detour                  string
	defaultOutbound         bool
	disableEmptyDirectCheck bool
}

func NewDetour(outboundManager adapter.OutboundManager, detour string, disableEmptyDirectCheck bool) N.Dialer {
	return &DetourDialer{
		outboundManager:         outboundManager,
		detour:                  detour,
		disableEmptyDirectCheck: disableEmptyDirectCheck,
	}
}

func NewDefaultOutboundDetour(outboundManager adapter.OutboundManager) N.Dialer {
	return &DetourDialer{
		outboundManager: outboundManager,
		defaultOutbound: true,
	}
}

func InitializeDetour(dialer N.Dialer) error {
	detourDialer, isDetour := common.Cast[*DetourDialer](dialer)
	if !isDetour {
		return nil
	}
	return common.Error(detourDialer.Dialer())
}

func (d *DetourDialer) Dialer() (N.Dialer, error) {
	var dialer adapter.Outbound
	if d.detour != "" {
		var loaded bool
		dialer, loaded = d.outboundManager.Outbound(d.detour)
		if !loaded {
			return nil, E.New("outbound detour not found: ", d.detour)
		}
	} else {
		dialer = d.outboundManager.Default()
	}
	if dialer == nil {
		return nil, E.New("default outbound not found")
	}
	if !d.defaultOutbound && !d.disableEmptyDirectCheck {
		if direct, ok := dialer.(DirectDialer); ok && direct.IsEmpty() {
			return nil, E.New("detour to an empty direct outbound makes no sense")
		}
	}
	return dialer, nil
}

func (d *DetourDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	dialer, err := d.Dialer()
	if err != nil {
		return nil, err
	}
	return dialer.DialContext(ctx, network, destination)
}

func (d *DetourDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	dialer, err := d.Dialer()
	if err != nil {
		return nil, err
	}
	return dialer.ListenPacket(ctx, destination)
}

func (d *DetourDialer) Upstream() any {
	detour, _ := d.Dialer()
	return detour
}
