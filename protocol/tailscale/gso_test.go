//go:build with_tailscale

package tailscale

import (
	"testing"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
)

func TestUDPGSOPerTailcatNode(t *testing.T) {
	enabledTrue, enabledFalse := true, false
	for _, enabled := range []*bool{nil, &enabledTrue, &enabledFalse} {
		outboundDialer, err := dialer.NewDefault(t.Context(), option.DialerOptions{AbstractDialerOptions: option.AbstractDialerOptions{UDPGSO: enabled}})
		if err != nil {
			t.Fatal(err)
		}
		want := enabled != nil && !*enabled
		if (systemBinding{}).hooks(outboundDialer).DisableUDPGSO != want {
			t.Fatal("magicsock hooks lost policy")
		}
	}
}
