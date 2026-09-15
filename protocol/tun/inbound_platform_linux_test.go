//go:build linux

package tun

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
)

type routeBypassTestPlatform struct {
	adapter.PlatformInterface
	open func(*tun.Options, bool) (tun.Tun, error)
}

func (*routeBypassTestPlatform) UsePlatformInterface() bool { return true }

func (p *routeBypassTestPlatform) OpenInterface(options *tun.Options, _ option.TunPlatformOptions, bypass bool) (tun.Tun, error) {
	return p.open(options, bypass)
}

type routeBypassTestNetwork struct{ adapter.NetworkManager }

func (*routeBypassTestNetwork) BridgeInterfaces() []string { return nil }

func TestPlatformVPNRouteBypassWithoutAddressSets(t *testing.T) {
	for _, autoRedirect := range []bool{false, true} {
		name := "ordinary VPN"
		if autoRedirect {
			name = "platform auto redirect"
		}
		t.Run(name, func(t *testing.T) {
			options := tun.Options{
				Name:                     "test-tun",
				AutoRoute:                true,
				Inet4Address:             []netip.Prefix{netip.MustParsePrefix("172.19.0.1/30")},
				Inet6Address:             []netip.Prefix{netip.MustParsePrefix("fdfe:dcba:9876::1/126")},
				Inet4RouteAddress:        []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
				Inet6RouteAddress:        []netip.Prefix{netip.MustParsePrefix("2000::/3")},
				Inet4RouteExcludeAddress: []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
			}
			stop := errors.New("stop before opening a real VPN interface")
			opened := false
			platform := &routeBypassTestPlatform{open: func(got *tun.Options, bypass bool) (tun.Tun, error) {
				opened = true
				if want := C.IsAndroid && autoRedirect; bypass != want {
					t.Errorf("VPN route bypass = %v, want %v without address sets", bypass, want)
				}
				if !reflect.DeepEqual(*got, options) {
					t.Errorf("platform options changed: got %+v, want %+v", *got, options)
				}
				return nil, stop
			}}
			logger := log.NewNOPFactory().NewLogger("test")
			ctx := context.Background()
			scope := adapter.NewScope(ctx, logger)
			defer scope.Close()
			inbound := &Inbound{
				ctx:                     ctx,
				logger:                  logger,
				tunOptions:              options,
				networkManager:          &routeBypassTestNetwork{},
				platformInterface:       platform,
				usePlatformInterface:    true,
				enableAutoRedirect:      autoRedirect,
				usePlatformAutoRedirect: autoRedirect,
			}
			if err := inbound.Start(adapter.StartStateStart, scope); !errors.Is(err, stop) {
				t.Fatalf("start: %v", err)
			}
			if !opened {
				t.Fatal("platform interface was not opened")
			}
		})
	}
}
