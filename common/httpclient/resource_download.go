package httpclient

import (
	"context"
	"net"

	"github.com/sagernet/sing-box/common/interrupt"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

// A dedicated pool also needs a marked dialer for engines that dial from a
// background context, such as the Apple HTTP proxy bridge.
func resourceDownloadDialer(dialer N.Dialer, enabled bool) N.Dialer {
	if !enabled {
		return dialer
	}
	return downloadDialer{dialer}
}

type downloadDialer struct {
	N.Dialer
}

func (d downloadDialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return d.Dialer.DialContext(interrupt.ContextWithIsResourceDownload(ctx), network, destination)
}

func (d downloadDialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return d.Dialer.ListenPacket(interrupt.ContextWithIsResourceDownload(ctx), destination)
}
