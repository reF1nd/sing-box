package dialer

import (
	"context"
	"net"
	"testing"

	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

func TestUDPGSOPerDialer(t *testing.T) {
	enabledTrue, enabledFalse := true, false
	receiver, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.Close()
	for _, enabled := range []*bool{nil, &enabledTrue, &enabledFalse} {
		dialer, err := NewDefault(context.Background(), option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{UDPGSO: enabled}})
		if err != nil {
			t.Fatal(err)
		}
		want := enabled != nil && !*enabled
		destination := M.SocksaddrFromNet(receiver.LocalAddr())
		conn, err := dialer.DialContext(context.Background(), "udp", destination)
		if err != nil {
			t.Fatal(err)
		}
		if N.IsGSODisabled(conn) != want {
			t.Fatal("connected socket lost policy")
		}
		conn.Close()
		packet, err := dialer.ListenPacket(context.Background(), destination)
		if err != nil {
			t.Fatal(err)
		}
		if N.IsGSODisabled(packet) != want {
			t.Fatal("unconnected socket lost policy")
		}
		packet.Close()
	}
}
