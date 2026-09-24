package wireguard

import (
	"encoding/base64"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/logger"
	N "github.com/sagernet/sing/common/network"
)

func TestUDPGSOPerEndpoint(t *testing.T) {
	outboundDialer, err := dialer.NewDefault(t.Context(), option.DialerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	for _, disabled := range []bool{false, true} {
		endpoint, err := NewEndpoint(EndpointOptions{
			Context:       t.Context(),
			Logger:        logger.NOP(),
			Dialer:        outboundDialer,
			DisableUDPGSO: disabled,
			PrivateKey:    base64.StdEncoding.EncodeToString(make([]byte, 32)),
			Address:       []netip.Prefix{netip.MustParsePrefix("172.16.0.2/32")},
		})
		if err != nil {
			t.Fatal(err)
		}
		err = endpoint.Initialize(nil)
		if err != nil {
			t.Fatal(err)
		}
		err = endpoint.Start(false)
		if err != nil {
			t.Fatal(err)
		}
		if N.IsGSODisabled(endpoint.device.Load().Bind()) != disabled {
			t.Fatal("standard bind lost policy")
		}
		err = endpoint.Close()
		if err != nil {
			t.Fatal(err)
		}
	}
}
