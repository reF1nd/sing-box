package group

import (
	"testing"

	"github.com/sagernet/sing-box/adapter"
	N "github.com/sagernet/sing/common/network"

	"github.com/stretchr/testify/require"
)

func TestSelectorSelectPreMatchOutbound(t *testing.T) {
	selectedOutbound := new(preMatchTestOutbound)
	selector := new(Selector)
	selector.selected.Store(selectedOutbound)

	outbound, action := selector.SelectPreMatchOutbound(new(adapter.InboundContext), selectPreMatchFlow)
	require.Same(t, selectedOutbound, outbound)
	require.Equal(t, adapter.PreMatchFlow, action)
}

func TestURLTestSelectPreMatchOutboundByNetwork(t *testing.T) {
	tcpOutbound := new(preMatchTestOutbound)
	udpOutbound := new(preMatchTestOutbound)
	urlTest := &URLTest{
		group: &URLTestGroup{
			selectedOutboundTCP: tcpOutbound,
			selectedOutboundUDP: udpOutbound,
		},
	}

	selectedTCP, tcpAction := urlTest.SelectPreMatchOutbound(&adapter.InboundContext{Network: N.NetworkTCP}, selectPreMatchFlow)
	selectedUDP, udpAction := urlTest.SelectPreMatchOutbound(&adapter.InboundContext{Network: N.NetworkUDP}, selectPreMatchFlow)
	selectedICMP, icmpAction := urlTest.SelectPreMatchOutbound(&adapter.InboundContext{Network: N.NetworkICMP}, selectPreMatchFlow)
	require.Same(t, tcpOutbound, selectedTCP)
	require.Equal(t, adapter.PreMatchFlow, tcpAction)
	require.Same(t, udpOutbound, selectedUDP)
	require.Equal(t, adapter.PreMatchFlow, udpAction)
	require.Same(t, tcpOutbound, selectedICMP)
	require.Equal(t, adapter.PreMatchFlow, icmpAction)
}

func selectPreMatchFlow(outbound adapter.Outbound) (adapter.Outbound, adapter.PreMatchAction) {
	return outbound, adapter.PreMatchFlow
}

type preMatchTestOutbound struct {
	adapter.Outbound
	tag string
}

func (o *preMatchTestOutbound) Tag() string {
	return o.tag
}
