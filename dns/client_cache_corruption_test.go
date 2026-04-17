package dns

import (
	"net/netip"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing/common/logger"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type corruptDNSCacheStore struct {
	rawMessage          []byte
	deletedTransportTag string
	deletedQuestionName string
	deletedQuestionType uint16
	deletedRawMessage   []byte
}

func (s *corruptDNSCacheStore) LoadDNSCache(string, string, uint16) ([]byte, time.Time, bool) {
	return s.rawMessage, time.Now().Add(time.Hour), true
}

func (*corruptDNSCacheStore) SaveDNSCache(string, string, uint16, []byte, time.Time) error {
	return nil
}

func (*corruptDNSCacheStore) SaveDNSCacheAsync(string, string, uint16, []byte, time.Time, logger.Logger) {
}

func (s *corruptDNSCacheStore) DeleteDNSCache(transportTag string, questionName string, questionType uint16, rawMessage []byte) {
	s.deletedTransportTag = transportTag
	s.deletedQuestionName = questionName
	s.deletedQuestionType = questionType
	s.deletedRawMessage = append([]byte(nil), rawMessage...)
}

func (*corruptDNSCacheStore) ClearDNSCache() error {
	return nil
}

var _ adapter.DNSCacheStore = (*corruptDNSCacheStore)(nil)

func TestLoadPersistentResponseDeletesMatchingClientSubnetEntry(t *testing.T) {
	t.Parallel()

	rawMessage := []byte{0x00}
	store := &corruptDNSCacheStore{rawMessage: rawMessage}
	client := &Client{dnsCache: store}
	key := dnsCacheKey{
		Question: mDNS.Question{
			Name:   "example.com.",
			Qtype:  mDNS.TypeA,
			Qclass: mDNS.ClassINET,
		},
		transportTag: "local",
		clientSubnet: netip.MustParsePrefix("192.0.2.0/24"),
	}

	response, ttl, isStale := client.loadPersistentResponse(key)

	require.Nil(t, response)
	require.Zero(t, ttl)
	require.False(t, isStale)
	require.Equal(t, key.persistentName(), store.deletedTransportTag)
	require.Equal(t, key.Name, store.deletedQuestionName)
	require.Equal(t, key.Qtype, store.deletedQuestionType)
	require.Equal(t, rawMessage, store.deletedRawMessage)
}
