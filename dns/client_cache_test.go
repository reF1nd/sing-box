package dns

import (
	"testing"
	"time"

	mDNS "github.com/miekg/dns"
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

	client.storeCache(nil, question, message, 60, &lazyCacheTTL)
	cacheEntry, loaded := client.cache.Get(question)
	require.True(t, loaded)
	cacheEntry.expireTime = time.Now().Add(-time.Second)

	response, _, stale := client.loadResponse(question, nil)
	require.NotNil(t, response)
	require.True(t, stale)
}
