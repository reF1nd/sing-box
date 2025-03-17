package dns

import (
	"net"
	"net/netip"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/cryptobyte"
)

func TestDNSLearnsECHPublicName(t *testing.T) {
	const queryName = "_8443._https.site.example."
	const publicName = "public.example"
	var echConfig cryptobyte.Builder
	echConfig.AddUint16LengthPrefixed(func(list *cryptobyte.Builder) {
		list.AddUint16(0xfe0d)
		list.AddUint16LengthPrefixed(func(config *cryptobyte.Builder) {
			config.AddUint8(1)
			config.AddUint16(0x20)
			config.AddUint16LengthPrefixed(func(key *cryptobyte.Builder) { key.AddBytes(make([]byte, 32)) })
			config.AddUint16LengthPrefixed(func(suite *cryptobyte.Builder) {
				suite.AddUint16(1)
				suite.AddUint16(1)
			})
			config.AddUint8(0)
			config.AddUint8LengthPrefixed(func(name *cryptobyte.Builder) { name.AddBytes([]byte(publicName)) })
			config.AddUint16(0)
		})
	})
	router, err := NewRouter(t.Context(), log.NewNOPFactory(), option.DNSOptions{
		RawDNSOptions: option.RawDNSOptions{ReverseMapping: true},
	})
	require.NoError(t, err)
	query := new(mDNS.Msg).SetQuestion(queryName, mDNS.TypeHTTPS)
	response := new(mDNS.Msg).SetReply(query)
	const address = "192.0.2.42"
	response.Answer = []mDNS.RR{&mDNS.HTTPS{SVCB: mDNS.SVCB{
		Hdr:      mDNS.RR_Header{Name: queryName, Rrtype: mDNS.TypeHTTPS, Class: mDNS.ClassINET, Ttl: 300},
		Priority: 1,
		Target:   ".",
		Value: []mDNS.SVCBKeyValue{
			&mDNS.SVCBECHConfig{ECH: echConfig.BytesOrPanic()},
			&mDNS.SVCBIPv4Hint{Hint: []net.IP{net.ParseIP(address).To4()}},
		},
	}}}
	router.recordReverseMapping(query, response, nil)
	domain, ok := router.LookupReverseMapping(netip.MustParseAddr(address))
	require.True(t, ok)
	require.Equal(t, "site.example", domain)
	require.Equal(t, publicName, router.LookupECHPublicName(domain))
	require.Equal(t, publicName, router.LookupECHPublicName("SITE.EXAMPLE."))
	require.Empty(t, router.LookupECHPublicName("unrelated.example"))

	// Mixed-case _HTTPS. service label must still evict the cached public name
	// when a subsequent successful HTTPS answer carries no ECH config.
	evictQuery := new(mDNS.Msg).SetQuestion("_8443._HTTPS.site.example.", mDNS.TypeHTTPS)
	evictResponse := new(mDNS.Msg).SetReply(evictQuery)
	evictResponse.Answer = []mDNS.RR{&mDNS.HTTPS{SVCB: mDNS.SVCB{
		Hdr:      mDNS.RR_Header{Name: "_8443._HTTPS.site.example.", Rrtype: mDNS.TypeHTTPS, Class: mDNS.ClassINET, Ttl: 300},
		Priority: 1,
		Target:   ".",
	}}}
	router.recordReverseMapping(evictQuery, evictResponse, nil)
	require.Empty(t, router.LookupECHPublicName("site.example"))

	// Learning via mixed-case _HTTPS. service label must also normalize to the origin domain.
	upperQuery := new(mDNS.Msg).SetQuestion("_8443._HTTPS.Site.Example.", mDNS.TypeHTTPS)
	upperResponse := new(mDNS.Msg).SetReply(upperQuery)
	upperResponse.Answer = []mDNS.RR{&mDNS.HTTPS{SVCB: mDNS.SVCB{
		Hdr:      mDNS.RR_Header{Name: "_8443._HTTPS.Site.Example.", Rrtype: mDNS.TypeHTTPS, Class: mDNS.ClassINET, Ttl: 300},
		Priority: 1,
		Target:   ".",
		Value: []mDNS.SVCBKeyValue{
			&mDNS.SVCBECHConfig{ECH: echConfig.BytesOrPanic()},
		},
	}}}
	router.recordReverseMapping(upperQuery, upperResponse, nil)
	require.Equal(t, publicName, router.LookupECHPublicName("site.example"))
}
