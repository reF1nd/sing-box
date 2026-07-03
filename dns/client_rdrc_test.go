package dns

import (
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"
	"github.com/stretchr/testify/require"
)

type keyedRDRCTestStore struct {
	access   sync.Mutex
	rejected map[adapter.DNSCacheKey]bool
}

func newKeyedRDRCTestStore() *keyedRDRCTestStore {
	return &keyedRDRCTestStore{rejected: make(map[adapter.DNSCacheKey]bool)}
}

func normalizeRDRCTestKey(key adapter.DNSCacheKey) adapter.DNSCacheKey {
	if key.ClientSubnet.IsValid() {
		key.ClientSubnet = key.ClientSubnet.Masked()
	}
	return key
}

func (s *keyedRDRCTestStore) LoadRDRC(transportName string, qName string, qType uint16) bool {
	return s.LoadRDRCWithKey(adapter.DNSCacheKey{TransportName: transportName, QuestionName: qName, QType: qType})
}

func (s *keyedRDRCTestStore) SaveRDRC(transportName string, qName string, qType uint16) error {
	return s.SaveRDRCWithKey(adapter.DNSCacheKey{TransportName: transportName, QuestionName: qName, QType: qType})
}

func (s *keyedRDRCTestStore) SaveRDRCAsync(transportName string, qName string, qType uint16, _ logger.Logger) {
	_ = s.SaveRDRC(transportName, qName, qType)
}

func (s *keyedRDRCTestStore) LoadRDRCWithKey(key adapter.DNSCacheKey) bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.rejected[normalizeRDRCTestKey(key)]
}

func (s *keyedRDRCTestStore) SaveRDRCWithKey(key adapter.DNSCacheKey) error {
	s.access.Lock()
	defer s.access.Unlock()
	s.rejected[normalizeRDRCTestKey(key)] = true
	return nil
}

func (s *keyedRDRCTestStore) SaveRDRCAsyncWithKey(key adapter.DNSCacheKey, _ logger.Logger) {
	_ = s.SaveRDRCWithKey(key)
}

func TestClientRDRCSeparatesClientSubnets(t *testing.T) {
	t.Parallel()

	store := newKeyedRDRCTestStore()
	client := NewClient(ClientOptions{
		DisableExpire: true,
		RDRC:          func() adapter.RDRCStore { return store },
	})
	client.Start()
	transport := newClientSubnetCacheTestTransport()
	clientSubnetA := netip.MustParsePrefix("1.1.1.123/24")
	clientSubnetB := netip.MustParsePrefix("2.2.2.0/24")
	rejectResponse := func([]netip.Addr) bool { return false }

	_, err, _ := client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{ClientSubnet: clientSubnetA}, rejectResponse)
	require.ErrorIs(t, err, ErrResponseRejected)
	_, err, _ = client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{ClientSubnet: clientSubnetA.Masked()}, rejectResponse)
	require.ErrorIs(t, err, ErrResponseRejectedCached)
	_, err, _ = client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{ClientSubnet: clientSubnetB}, rejectResponse)
	require.ErrorIs(t, err, ErrResponseRejected)

	require.Equal(t, 1, transport.exchangeCount(clientSubnetA.Masked()))
	require.Equal(t, 1, transport.exchangeCount(clientSubnetB))
}

func TestClientRDRCHonorsForwardedClientSubnetCacheOption(t *testing.T) {
	t.Parallel()

	store := newKeyedRDRCTestStore()
	client := NewClient(ClientOptions{
		DisableExpire:     true,
		CacheClientSubnet: true,
		RDRC:              func() adapter.RDRCStore { return store },
	})
	client.Start()
	transport := newClientSubnetCacheTestTransport()
	clientSubnet := netip.MustParsePrefix("1.1.1.0/24")
	rejectResponse := func([]netip.Addr) bool { return false }

	_, err, _ := client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnet), adapter.DNSQueryOptions{}, rejectResponse)
	require.ErrorIs(t, err, ErrResponseRejected)
	_, err, _ = client.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnet), adapter.DNSQueryOptions{}, rejectResponse)
	require.ErrorIs(t, err, ErrResponseRejectedCached)
	require.Equal(t, 1, transport.exchangeCount(clientSubnet))

	readOnlyClient := NewClient(ClientOptions{
		DisableExpire: true,
		RDRC:          func() adapter.RDRCStore { return store },
	})
	readOnlyClient.Start()
	_, err, _ = readOnlyClient.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, clientSubnet), adapter.DNSQueryOptions{}, rejectResponse)
	require.ErrorIs(t, err, ErrResponseRejectedCached)
	require.Equal(t, 1, transport.exchangeCount(clientSubnet))

	uncachedSubnet := netip.MustParsePrefix("2.2.2.0/24")
	for range 2 {
		_, err, _ = readOnlyClient.Exchange(context.Background(), transport, newForwardedClientSubnetCacheQuery(t, uncachedSubnet), adapter.DNSQueryOptions{}, rejectResponse)
		require.ErrorIs(t, err, ErrResponseRejected)
	}
	require.Equal(t, 2, transport.exchangeCount(uncachedSubnet))
}

type legacyRDRCTestStore struct {
	access   sync.Mutex
	rejected map[adapter.DNSCacheKey]bool
}

func (s *legacyRDRCTestStore) LoadRDRC(transportName string, qName string, qType uint16) bool {
	s.access.Lock()
	defer s.access.Unlock()
	return s.rejected[adapter.DNSCacheKey{TransportName: transportName, QuestionName: qName, QType: qType}]
}

func (s *legacyRDRCTestStore) SaveRDRC(transportName string, qName string, qType uint16) error {
	s.access.Lock()
	defer s.access.Unlock()
	s.rejected[adapter.DNSCacheKey{TransportName: transportName, QuestionName: qName, QType: qType}] = true
	return nil
}

func (s *legacyRDRCTestStore) SaveRDRCAsync(transportName string, qName string, qType uint16, _ logger.Logger) {
	_ = s.SaveRDRC(transportName, qName, qType)
}

func TestClientRDRCKeepsLegacyStoreCompatible(t *testing.T) {
	t.Parallel()

	store := &legacyRDRCTestStore{rejected: make(map[adapter.DNSCacheKey]bool)}
	client := NewClient(ClientOptions{
		DisableExpire: true,
		RDRC:          func() adapter.RDRCStore { return store },
	})
	client.Start()
	transport := newClientSubnetCacheTestTransport()
	rejectResponse := func([]netip.Addr) bool { return false }

	_, err, _ := client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{}, rejectResponse)
	require.ErrorIs(t, err, ErrResponseRejected)
	_, err, _ = client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{}, rejectResponse)
	require.ErrorIs(t, err, ErrResponseRejectedCached)

	clientSubnet := netip.MustParsePrefix("1.1.1.0/24")
	for range 2 {
		_, err, _ = client.Exchange(context.Background(), transport, newClientSubnetCacheQuery(), adapter.DNSQueryOptions{ClientSubnet: clientSubnet}, rejectResponse)
		require.ErrorIs(t, err, ErrResponseRejected)
	}
	require.Equal(t, 2, transport.exchangeCount(clientSubnet))
}
