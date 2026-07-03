package dns

import (
	"context"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common/logger"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type legacyDNSCacheStore struct{}

var _ adapter.DNSCacheStore = (*legacyDNSCacheStore)(nil)

func (*legacyDNSCacheStore) LoadDNSCache(string, string, uint16) ([]byte, time.Time, bool) {
	return nil, time.Time{}, false
}

func (*legacyDNSCacheStore) SaveDNSCache(string, string, uint16, []byte, time.Time) error {
	return nil
}

func (*legacyDNSCacheStore) SaveDNSCacheAsync(string, string, uint16, []byte, time.Time, logger.Logger) {
}

func (*legacyDNSCacheStore) DeleteDNSCache(string, string, uint16) {}
func (*legacyDNSCacheStore) ClearDNSCache() error                  { return nil }

type clientSubnetRDRCTestStore struct {
	access   sync.Mutex
	rejected map[adapter.DNSCacheKey]bool
}

var _ adapter.RDRCStore = (*clientSubnetRDRCTestStore)(nil)
var _ adapter.RDRCStoreWithKey = (*clientSubnetRDRCTestStore)(nil)

func newClientSubnetRDRCTestStore() *clientSubnetRDRCTestStore {
	return &clientSubnetRDRCTestStore{rejected: make(map[adapter.DNSCacheKey]bool)}
}

func normalizeClientSubnetRDRCTestKey(key adapter.DNSCacheKey) adapter.DNSCacheKey {
	if key.ClientSubnet.IsValid() {
		key.ClientSubnet = key.ClientSubnet.Masked()
	}
	return key
}

func (s *clientSubnetRDRCTestStore) LoadRDRC(transportName string, qName string, qType uint16) bool {
	return s.LoadRDRCWithKey(adapter.DNSCacheKey{TransportName: transportName, QuestionName: qName, QType: qType})
}

func (s *clientSubnetRDRCTestStore) SaveRDRC(transportName string, qName string, qType uint16) error {
	return s.SaveRDRCWithKey(adapter.DNSCacheKey{TransportName: transportName, QuestionName: qName, QType: qType})
}

func (s *clientSubnetRDRCTestStore) SaveRDRCAsync(transportName string, qName string, qType uint16, _ logger.Logger) {
	s.SaveRDRCAsyncWithKey(adapter.DNSCacheKey{TransportName: transportName, QuestionName: qName, QType: qType}, nil)
}

func (s *clientSubnetRDRCTestStore) LoadRDRCWithKey(key adapter.DNSCacheKey) bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.rejected[normalizeClientSubnetRDRCTestKey(key)]
}

func (s *clientSubnetRDRCTestStore) SaveRDRCWithKey(key adapter.DNSCacheKey) error {
	s.access.Lock()
	s.rejected[normalizeClientSubnetRDRCTestKey(key)] = true
	s.access.Unlock()
	return nil
}

func (s *clientSubnetRDRCTestStore) SaveRDRCAsyncWithKey(key adapter.DNSCacheKey, _ logger.Logger) {
	_ = s.SaveRDRCWithKey(key)
}

type clientSubnetCacheTestTransport struct {
	TransportAdapter
	access    sync.Mutex
	exchanges map[netip.Prefix]int
	addresses map[netip.Prefix]netip.Addr
}

func newClientSubnetCacheTestTransport() *clientSubnetCacheTestTransport {
	return &clientSubnetCacheTestTransport{
		TransportAdapter: NewTransportAdapter("test", "test", nil),
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

	client := NewClient(ClientOptions{Context: context.Background(), DisableExpire: true})
	transport := newClientSubnetCacheTestTransport()
	clientSubnetA := netip.MustParsePrefix("1.1.1.123/24")
	clientSubnetANormalized := clientSubnetA.Masked()
	clientSubnetB := netip.MustParsePrefix("2.2.2.0/24")

	_, err := client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{ClientSubnet: clientSubnetA}, nil)
	require.NoError(t, err)
	_, err = client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{ClientSubnet: clientSubnetANormalized}, nil)
	require.NoError(t, err)
	_, err = client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{ClientSubnet: clientSubnetB}, nil)
	require.NoError(t, err)
	_, err = client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	require.Equal(t, 1, transport.exchangeCount(clientSubnetANormalized))
	require.Equal(t, 1, transport.exchangeCount(clientSubnetB))
	require.Equal(t, 1, transport.exchangeCount(netip.Prefix{}))
}

func TestClientLookupCachesConfiguredClientSubnet(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{Context: context.Background(), DisableExpire: true})
	transport := newClientSubnetCacheTestTransport()
	clientSubnet := netip.MustParsePrefix("1.1.1.0/24")
	options := adapter.DNSQueryOptions{
		Strategy:     C.DomainStrategyIPv4Only,
		ClientSubnet: clientSubnet,
	}

	first, err := client.Lookup(context.Background(), transport, "example.com", options, nil)
	require.NoError(t, err)
	second, err := client.Lookup(context.Background(), transport, "example.com", options, nil)
	require.NoError(t, err)

	require.Equal(t, first, second)
	require.Equal(t, 1, transport.exchangeCount(clientSubnet))
}

func TestClientUsesClientSubnetRDRC(t *testing.T) {
	t.Parallel()

	rdrcStore := newClientSubnetRDRCTestStore()
	client := NewClient(ClientOptions{
		Context: context.Background(),
		RDRC: func() adapter.RDRCStore {
			return rdrcStore
		},
	})
	client.Start()
	transport := newClientSubnetCacheTestTransport()
	clientSubnet := netip.MustParsePrefix("1.1.1.0/24")
	options := adapter.DNSQueryOptions{ClientSubnet: clientSubnet}
	rejectResponse := func(*mDNS.Msg) bool { return false }

	_, err := client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), options, rejectResponse)
	require.ErrorIs(t, err, ErrResponseRejected)
	_, err = client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnet), adapter.DNSQueryOptions{}, rejectResponse)
	require.ErrorIs(t, err, ErrResponseRejectedCached)
	require.Equal(t, 1, transport.exchangeCount(clientSubnet))
}

func TestClientDoesNotCacheForwardedClientSubnet(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{Context: context.Background(), DisableExpire: true})
	transport := newClientSubnetCacheTestTransport()
	clientSubnet := netip.MustParsePrefix("1.1.1.0/24")

	_, err := client.Exchange(context.Background(), transport, SetClientSubnet(newClientSubnetCacheQuery(), clientSubnet), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	_, err = client.Exchange(context.Background(), transport, SetClientSubnet(newClientSubnetCacheQuery(), clientSubnet), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	require.Equal(t, 2, transport.exchangeCount(clientSubnet))
}

func TestClientReadsExistingForwardedClientSubnetCacheWhenDisabled(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{
		Context:           context.Background(),
		DisableExpire:     true,
		CacheClientSubnet: true,
	})
	transport := newClientSubnetCacheTestTransport()
	clientSubnet := netip.MustParsePrefix("1.1.1.0/24")

	_, err := client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnet), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	client.cacheClientSubnet = false
	cached, err := client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnet), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	require.Equal(t, 1, transport.exchangeCount(clientSubnet))
	require.Equal(t, clientSubnet, clientSubnetFromMessage(cached))
}

func TestClientCachesForwardedClientSubnetWhenEnabled(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{
		Context:           context.Background(),
		DisableExpire:     true,
		CacheClientSubnet: true,
	})
	transport := newClientSubnetCacheTestTransport()
	clientSubnetA := netip.MustParsePrefix("1.1.1.0/24")
	clientSubnetB := netip.MustParsePrefix("2.2.2.0/24")

	_, err := client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnetA), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	cached, err := client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnetA), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	_, err = client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnetB), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	require.Equal(t, 1, transport.exchangeCount(clientSubnetA))
	require.Equal(t, 1, transport.exchangeCount(clientSubnetB))
	require.Equal(t, clientSubnetA, clientSubnetFromMessage(cached))
}

func TestClientDoesNotCacheClientSubnetWithAdditionalEDNSOptions(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{
		Context:           context.Background(),
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

	_, err := client.Exchange(context.Background(), transport, newQuery(), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	_, err = client.Exchange(context.Background(), transport, newQuery(), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	require.Equal(t, 2, transport.exchangeCount(clientSubnet))
}

func TestClientSubnetCacheFallsBackForLegacyPersistentStore(t *testing.T) {
	t.Parallel()

	legacyStore := new(legacyDNSCacheStore)
	client := NewClient(ClientOptions{
		Context:           context.Background(),
		DisableExpire:     true,
		CacheClientSubnet: true,
		DNSCache: func() adapter.DNSCacheStore {
			return legacyStore
		},
	})
	client.Start()
	transport := newClientSubnetCacheTestTransport()
	clientSubnet := netip.MustParsePrefix("1.1.1.0/24")

	_, err := client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnet), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	_, err = client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnet), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	require.NotNil(t, client.cache)
	require.Equal(t, 1, transport.exchangeCount(clientSubnet))
}

func TestClientOptimisticRefreshKeepsClientSubnetCacheNamespace(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{
		Context:           context.Background(),
		OptimisticTimeout: time.Hour,
	})
	transport := newClientSubnetCacheTestTransport()
	clientSubnet := netip.MustParsePrefix("1.1.1.0/24")
	question := newClientSubnetCacheQuery().Question[0]
	cacheKey := dnsCacheKey{
		Question:     question,
		transportTag: transport.Tag(),
		clientSubnet: clientSubnet,
	}
	staleResponse := clientSubnetCacheResponse(newClientSubnetCacheQuery(), netip.MustParseAddr("198.51.100.1"))
	client.cache.AddWithLifetime(cacheKey, &dnsMsg{msg: staleResponse}, -time.Second)

	addresses, err := client.Lookup(context.Background(), transport, "example.com", adapter.DNSQueryOptions{
		Strategy:     C.DomainStrategyIPv4Only,
		ClientSubnet: clientSubnet,
	}, nil)
	require.NoError(t, err)
	require.Equal(t, []netip.Addr{netip.MustParseAddr("198.51.100.1")}, addresses)

	require.Eventually(t, func() bool {
		response, _, stale := client.loadResponse(cacheKey)
		return response != nil && !stale && MessageToAddresses(response)[0] != netip.MustParseAddr("198.51.100.1")
	}, time.Second, 10*time.Millisecond)
	nonECSKey := cacheKey
	nonECSKey.clientSubnet = netip.Prefix{}
	response, _, _ := client.loadResponse(nonECSKey)
	require.Nil(t, response)
}

func TestClientSubnetCacheDisabledDoesNotRefreshStaleEntry(t *testing.T) {
	t.Parallel()

	client := NewClient(ClientOptions{
		Context:           context.Background(),
		OptimisticTimeout: time.Hour,
	})
	transport := newClientSubnetCacheTestTransport()
	clientSubnet := netip.MustParsePrefix("1.1.1.0/24")
	question := newClientSubnetCacheQuery().Question[0]
	cacheKey := dnsCacheKey{
		Question:     question,
		transportTag: transport.Tag(),
		clientSubnet: clientSubnet,
	}
	staleResponse := clientSubnetCacheResponse(newClientSubnetCacheQuery(), netip.MustParseAddr("198.51.100.1"))
	client.cache.AddWithLifetime(cacheKey, &dnsMsg{msg: staleResponse}, -time.Second)

	_, err := client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnet), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)
	_, err = client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnet), adapter.DNSQueryOptions{}, nil)
	require.NoError(t, err)

	require.Equal(t, 2, transport.exchangeCount(clientSubnet))
	_, _, stale := client.loadResponse(cacheKey)
	require.True(t, stale)
}
