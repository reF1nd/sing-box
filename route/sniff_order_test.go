package route

import (
	"context"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/sniff"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
	R "github.com/sagernet/sing-box/route/rule"
	"github.com/sagernet/sing/common/logger"

	"github.com/stretchr/testify/require"
)

func TestPacketSniffSpecificProtocolsBeforeQUICShortHeader(t *testing.T) {
	utpSYN := make([]byte, 20)
	utpSYN[0] = 0x41
	shortHeader := append([]byte{0x40}, make([]byte, 20)...)
	for _, names := range [][]string{nil, {C.ProtocolQUIC, C.ProtocolBitTorrent}, {C.ProtocolBitTorrent, C.ProtocolQUIC}} {
		action, err := R.NewRuleAction(context.Background(), logger.NOP(), option.RuleAction{
			Action:       C.RuleActionTypeSniff,
			SniffOptions: option.RouteActionSniff{Sniffer: names},
		})
		require.NoError(t, err)
		sniffers := action.(*R.RuleActionSniff).PacketSniffers
		if len(sniffers) == 0 {
			sniffers = defaultPacketSniffers
		}
		for _, testCase := range []struct {
			packet   []byte
			protocol string
		}{
			{utpSYN, C.ProtocolBitTorrent},
			{shortHeader, C.ProtocolQUIC},
		} {
			var metadata adapter.InboundContext
			err = sniff.PeekPacket(context.Background(), &metadata, testCase.packet, sniffers...)
			require.NoError(t, err)
			require.Equalf(t, testCase.protocol, metadata.Protocol, "sniffers: %v", names)
		}
	}
}
