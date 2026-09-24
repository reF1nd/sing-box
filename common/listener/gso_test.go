package listener

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/option"
	N "github.com/sagernet/sing/common/network"
)

func TestUDPGSOPerListener(t *testing.T) {
	enabledTrue, enabledFalse := true, false
	for _, enabled := range []*bool{nil, &enabledTrue, &enabledFalse} {
		listener := New(Options{Context: context.Background(), DisableLog: true, Listen: option.ListenOptions{UDPGSO: enabled}})
		conn, err := listener.ListenUDP()
		if err != nil {
			t.Fatal(err)
		}
		want := enabled != nil && !*enabled
		if N.IsGSODisabled(conn) != want {
			t.Fatal("protocol listener lost policy")
		}
		if N.IsGSODisabled(listener.udpPacketConn()) != want {
			t.Fatal("reply batch writer lost policy")
		}
		listener.Close()
	}
}
