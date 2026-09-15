package libbox

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/sagernet/sing-box/option"
	tun "github.com/sagernet/sing-tun"
)

func TestAndroidVPNRouteBypassPreservesRouteAddress(t *testing.T) {
	prefixes := func(values ...string) []netip.Prefix {
		var result []netip.Prefix
		for _, value := range values {
			result = append(result, netip.MustParsePrefix(value))
		}
		return result
	}
	for _, test := range []struct {
		name    string
		include []netip.Prefix
		exclude []netip.Prefix
	}{
		{"implicit default", nil, nil},
		{"explicit defaults", prefixes("0.0.0.0/0", "::/0"), nil},
		{"partial routes", prefixes("192.0.2.0/24", "2001:db8::/32"), nil},
		{"overlapping exclusions", prefixes("0.0.0.0/0", "10.0.0.0/8", "::/0"), prefixes("0.0.0.0/1", "::/0")},
	} {
		t.Run(test.name, func(t *testing.T) {
			options := &tun.Options{
				AutoRoute:    true,
				Inet4Address: prefixes("172.19.0.1/30"),
				Inet6Address: prefixes("fdfe:dcba:9876::1/126"),
			}
			for _, prefix := range test.include {
				if prefix.Addr().Is4() {
					options.Inet4RouteAddress = append(options.Inet4RouteAddress, prefix)
				} else {
					options.Inet6RouteAddress = append(options.Inet6RouteAddress, prefix)
				}
			}
			for _, prefix := range test.exclude {
				if prefix.Addr().Is4() {
					options.Inet4RouteExcludeAddress = append(options.Inet4RouteExcludeAddress, prefix)
				} else {
					options.Inet6RouteExcludeAddress = append(options.Inet6RouteExcludeAddress, prefix)
				}
			}
			routeRanges, err := options.BuildAutoRouteRanges(true)
			if err != nil {
				t.Fatal(err)
			}
			for _, bypass := range []bool{false, true} {
				platform := &tunOptions{options, routeRanges, option.TunPlatformOptions{AndroidVPNRouteBypass: bypass}}
				if platform.GetAndroidVPNRouteBypass() != bypass {
					t.Fatal("lost platform route bypass flag")
				}
				read := func(iterator RoutePrefixIterator) []netip.Prefix {
					var result []netip.Prefix
					for iterator.HasNext() {
						result = append(result, netip.MustParsePrefix(iterator.Next().String()))
					}
					return result
				}
				for _, pair := range []struct {
					got  []netip.Prefix
					want []netip.Prefix
				}{
					{read(platform.GetInet4RouteAddress()), options.Inet4RouteAddress},
					{read(platform.GetInet6RouteAddress()), options.Inet6RouteAddress},
					{read(platform.GetInet4RouteExcludeAddress()), options.Inet4RouteExcludeAddress},
					{read(platform.GetInet6RouteExcludeAddress()), options.Inet6RouteExcludeAddress},
					{append(read(platform.GetInet4RouteRange()), read(platform.GetInet6RouteRange())...), routeRanges},
				} {
					if !slices.Equal(pair.got, pair.want) {
						t.Fatalf("bypass=%v: routes %v, want %v", bypass, pair.got, pair.want)
					}
				}
			}
		})
	}
}
