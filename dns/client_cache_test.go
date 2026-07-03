package dns

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/stretchr/testify/require"
)

func TestClientRuleLazyCacheWithoutGlobalLazyCache(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{})
	lazyCacheTTL := uint32(3600)
	question := mDNS.Question{
		Name:   "example.com.",
		Qtype:  mDNS.TypeA,
		Qclass: mDNS.ClassINET,
	}
	message := &mDNS.Msg{Question: []mDNS.Question{question}}
	cacheKey := dnsCacheKey{Question: question}

	client.storeCache(cacheKey, nil, message, 60, &lazyCacheTTL)
	cacheEntry, loaded := client.cache.Get(cacheKey)
	require.True(t, loaded)
	cacheEntry.expireTime = time.Now().Add(-time.Second)

	response, _, stale := client.loadResponse(cacheKey, nil)
	require.NotNil(t, response)
	require.True(t, stale)
}

type clientSubnetCacheTestTransport struct {
	TransportAdapter
	access    sync.Mutex
	exchanges map[netip.Prefix]int
	addresses map[netip.Prefix]netip.Addr
}

func newClientSubnetCacheTestTransport() *clientSubnetCacheTestTransport {
	return newClientSubnetCacheTestTransportWithTag("test")
}

func newClientSubnetCacheTestTransportWithTag(tag string) *clientSubnetCacheTestTransport {
	return &clientSubnetCacheTestTransport{
		TransportAdapter: NewTransportAdapter("test", tag, nil),
		exchanges:        make(map[netip.Prefix]int),
		addresses:        make(map[netip.Prefix]netip.Addr),
	}
}

func (t *clientSubnetCacheTestTransport) Start(adapter.StartStage) error { return nil }
func (t *clientSubnetCacheTestTransport) Close() error                   { return nil }
func (t *clientSubnetCacheTestTransport) Reset()                         {}

func (t *clientSubnetCacheTestTransport) Exchange(_ context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	clientSubnet := clientSubnetFromMessage(message)
	t.access.Lock()
	t.exchanges[clientSubnet]++
	address, loaded := t.addresses[clientSubnet]
	if !loaded {
		address = netip.AddrFrom4([4]byte{192, 0, 2, byte(len(t.addresses) + 1)})
		t.addresses[clientSubnet] = address
	}
	t.access.Unlock()
	response := clientSubnetCacheResponse(message, address)
	if clientSubnet.IsValid() {
		response = SetClientSubnet(response, clientSubnet)
	}
	return response, nil
}

func (t *clientSubnetCacheTestTransport) exchangeCount(clientSubnet netip.Prefix) int {
	t.access.Lock()
	defer t.access.Unlock()
	return t.exchanges[clientSubnet]
}

func clientSubnetFromMessage(message *mDNS.Msg) netip.Prefix {
	for _, record := range message.Extra {
		optRecord, isOPT := record.(*mDNS.OPT)
		if !isOPT {
			continue
		}
		for _, option := range optRecord.Option {
			subnetOption, isSubnet := option.(*mDNS.EDNS0_SUBNET)
			if !isSubnet {
				continue
			}
			clientSubnet, clientSubnetValid := clientSubnetFromOption(subnetOption)
			if clientSubnetValid {
				return clientSubnet
			}
			return netip.Prefix{}
		}
	}
	return netip.Prefix{}
}

func clientSubnetCacheResponse(message *mDNS.Msg, address netip.Addr) *mDNS.Msg {
	response := new(mDNS.Msg)
	response.SetReply(message)
	if message.Question[0].Qtype == mDNS.TypeA {
		response.Answer = []mDNS.RR{&mDNS.A{
			Hdr: mDNS.RR_Header{
				Name:   message.Question[0].Name,
				Rrtype: mDNS.TypeA,
				Class:  mDNS.ClassINET,
				Ttl:    60,
			},
			A: net.IP(address.AsSlice()),
		}}
	}
	return response
}

func newClientSubnetCacheQuery() *mDNS.Msg {
	message := new(mDNS.Msg)
	message.SetQuestion("example.com.", mDNS.TypeA)
	return message
}

func newForwardedClientSubnetCacheQuery(t *testing.T, clientSubnet netip.Prefix) *mDNS.Msg {
	t.Helper()
	message := SetClientSubnet(newClientSubnetCacheQuery(), clientSubnet)
	message.IsEdns0().SetUDPSize(1232)
	packed, err := message.Pack()
	require.NoError(t, err)
	unpacked := new(mDNS.Msg)
	require.NoError(t, unpacked.Unpack(packed))
	return unpacked
}

func TestClientCachesConfiguredClientSubnet(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{DisableExpire: true})
	transport := newClientSubnetCacheTestTransport()
	clientSubnetA := netip.MustParsePrefix("1.1.1.123/24")
	clientSubnetANormalized := clientSubnetA.Masked()
	clientSubnetB := netip.MustParsePrefix("2.2.2.0/24")

	_, err, _ := client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{ClientSubnet: clientSubnetA}, nil)
	require.NoError(t, err)
	_, err, _ = client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{ClientSubnet: clientSubnetANormalized}, nil)
	require.NoError(t, err)
	_, err, _ = client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{ClientSubnet: clientSubnetB}, nil)
	require.NoError(t, err)
	_, err, _ = client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	require.Equal(t, 1, transport.exchangeCount(clientSubnetANormalized))
	require.Equal(t, 1, transport.exchangeCount(clientSubnetB))
	require.Equal(t, 1, transport.exchangeCount(netip.Prefix{}))
}

func TestClientCachesConfiguredClientSubnetIndependently(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{DisableExpire: true, IndependentCache: true})
	transport := newClientSubnetCacheTestTransport()
	clientSubnetA := netip.MustParsePrefix("1.1.1.0/24")
	clientSubnetB := netip.MustParsePrefix("2.2.2.0/24")

	_, err, _ := client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{ClientSubnet: clientSubnetA}, nil)
	require.NoError(t, err)
	_, err, _ = client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{ClientSubnet: clientSubnetA}, nil)
	require.NoError(t, err)
	_, err, _ = client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{ClientSubnet: clientSubnetB}, nil)
	require.NoError(t, err)

	require.Equal(t, 1, transport.exchangeCount(clientSubnetA))
	require.Equal(t, 1, transport.exchangeCount(clientSubnetB))
}

func TestClientCachesConfiguredClientSubnetIndependentlyByTransport(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{DisableExpire: true, IndependentCache: true})
	transportA := newClientSubnetCacheTestTransportWithTag("test-a")
	transportB := newClientSubnetCacheTestTransportWithTag("test-b")
	clientSubnet := netip.MustParsePrefix("1.1.1.0/24")
	options := adapter.DNSQueryOptions{ClientSubnet: clientSubnet}

	for range 2 {
		_, err, _ := client.Exchange(context.Background(), transportA, newClientSubnetCacheQuery(), options, nil)
		require.NoError(t, err)
		_, err, _ = client.Exchange(context.Background(), transportB, newClientSubnetCacheQuery(), options, nil)
		require.NoError(t, err)
	}

	require.Equal(t, 1, transportA.exchangeCount(clientSubnet))
	require.Equal(t, 1, transportB.exchangeCount(clientSubnet))
}

func TestClientLookupCachesConfiguredClientSubnet(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{DisableExpire: true})
	transport := newClientSubnetCacheTestTransport()
	clientSubnet := netip.MustParsePrefix("1.1.1.0/24")
	options := adapter.DNSQueryOptions{
		Strategy:     C.DomainStrategyIPv4Only,
		ClientSubnet: clientSubnet,
	}

	first, err, _ := client.Lookup(context.Background(), transport, "example.com", options, nil)
	require.NoError(t, err)
	second, err, _ := client.Lookup(context.Background(), transport, "example.com", options, nil)
	require.NoError(t, err)

	require.Equal(t, first, second)
	require.Equal(t, 1, transport.exchangeCount(clientSubnet))
}

func TestClientDoesNotCacheForwardedClientSubnet(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{DisableExpire: true})
	transport := newClientSubnetCacheTestTransport()
	clientSubnet := netip.MustParsePrefix("1.1.1.0/24")

	_, err, _ := client.Exchange(context.Background(), transport, SetClientSubnet(newClientSubnetCacheQuery(), clientSubnet), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	_, err, _ = client.Exchange(context.Background(), transport, SetClientSubnet(newClientSubnetCacheQuery(), clientSubnet), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	require.Equal(t, 2, transport.exchangeCount(clientSubnet))
}

func TestClientReadsExistingForwardedClientSubnetCacheWhenDisabled(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{
		DisableExpire:     true,
		CacheClientSubnet: true,
	})
	transport := newClientSubnetCacheTestTransport()
	clientSubnet := netip.MustParsePrefix("1.1.1.0/24")

	_, err, _ := client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnet), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	client.cacheClientSubnet = false
	cached, err, _ := client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnet), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	require.Equal(t, 1, transport.exchangeCount(clientSubnet))
	require.Equal(t, clientSubnet, clientSubnetFromMessage(cached))
}

func TestClientCachesForwardedClientSubnetWhenEnabled(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{
		DisableExpire:     true,
		CacheClientSubnet: true,
	})
	transport := newClientSubnetCacheTestTransport()
	clientSubnetA := netip.MustParsePrefix("1.1.1.0/24")
	clientSubnetB := netip.MustParsePrefix("2.2.2.0/24")

	_, err, _ := client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnetA), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	cached, err, _ := client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnetA), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	_, err, _ = client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnetB), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	require.Equal(t, 1, transport.exchangeCount(clientSubnetA))
	require.Equal(t, 1, transport.exchangeCount(clientSubnetB))
	require.Equal(t, clientSubnetA, clientSubnetFromMessage(cached))
}

func TestClientDoesNotCacheClientSubnetWithAdditionalEDNSOptions(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{
		DisableExpire:     true,
		CacheClientSubnet: true,
	})
	transport := newClientSubnetCacheTestTransport()
	clientSubnet := netip.MustParsePrefix("1.1.1.0/24")
	newQuery := func() *mDNS.Msg {
		message := newForwardedClientSubnetCacheQuery(t, clientSubnet)
		message.IsEdns0().Option = append(message.IsEdns0().Option, &mDNS.EDNS0_COOKIE{
			Code:   mDNS.EDNS0COOKIE,
			Cookie: "0102030405060708",
		})
		return message
	}

	_, err, _ := client.Exchange(context.Background(), transport, newQuery(), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	_, err, _ = client.Exchange(context.Background(), transport, newQuery(), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	require.Equal(t, 2, transport.exchangeCount(clientSubnet))
}

func TestClientLazyCacheKeepsClientSubnetCacheNamespace(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{
		LazyCacheTTL: 3600,
	})
	transport := newClientSubnetCacheTestTransport()
	clientSubnet := netip.MustParsePrefix("1.1.1.0/24")
	question := newClientSubnetCacheQuery().Question[0]
	cacheKey := dnsCacheKey{
		Question:     question,
		clientSubnet: clientSubnet,
	}
	staleResponse := clientSubnetCacheResponse(newClientSubnetCacheQuery(), netip.MustParseAddr("198.51.100.1"))
	client.cache.AddWithLifetime(cacheKey, &dnsMsg{msg: staleResponse, expireTime: time.Now().Add(-time.Second), lazyCache: true}, time.Hour)

	addresses, err, stale := client.Lookup(context.Background(), transport, "example.com", adapter.DNSQueryOptions{
		Strategy:     C.DomainStrategyIPv4Only,
		ClientSubnet: clientSubnet,
	}, nil)
	require.NoError(t, err)
	require.True(t, stale)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("198.51.100.1")}, addresses)

	nonECSKey := cacheKey
	nonECSKey.clientSubnet = netip.Prefix{}
	response, _, _ := client.loadResponse(nonECSKey, transport)
	require.Nil(t, response)
}

func TestClientSubnetCacheDisabledDoesNotRefreshStaleEntry(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{
		LazyCacheTTL: 3600,
	})
	transport := newClientSubnetCacheTestTransport()
	clientSubnet := netip.MustParsePrefix("1.1.1.0/24")
	question := newClientSubnetCacheQuery().Question[0]
	cacheKey := dnsCacheKey{
		Question:     question,
		clientSubnet: clientSubnet,
	}
	staleResponse := clientSubnetCacheResponse(newClientSubnetCacheQuery(), netip.MustParseAddr("198.51.100.1"))
	client.cache.AddWithLifetime(cacheKey, &dnsMsg{msg: staleResponse, expireTime: time.Now().Add(-time.Second), lazyCache: true}, time.Hour)

	_, err, _ := client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnet), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	_, err, _ = client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnet), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	require.Equal(t, 2, transport.exchangeCount(clientSubnet))
	_, _, stale := client.loadResponse(cacheKey, transport)
	require.True(t, stale)
}
