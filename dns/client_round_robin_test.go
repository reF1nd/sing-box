package dns

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/adapter"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

func TestRoundRobinCacheIsolation(t *testing.T) {
	for _, persistent := range []bool{false, true} {
		t.Run(map[bool]string{false: "memory", true: "persistent"}[persistent], func(t *testing.T) {
			msg := new(mDNS.Msg)
			msg.SetQuestion("example.org.", mDNS.TypeA)
			for _, rr := range []string{"example.org. 300 IN CNAME target.org.", "target.org. 300 IN A 192.0.2.1", "target.org. 300 IN A 192.0.2.2", "target.org. 300 IN AAAA 2001:db8::1", "target.org. 300 IN AAAA 2001:db8::2"} {
				record, err := mDNS.NewRR(rr)
				require.NoError(t, err)
				msg.Answer = append(msg.Answer, record)
			}
			original := msg.String()
			options := ClientOptions{Context: context.Background(), RoundRobinCache: true}
			if persistent {
				packed, err := msg.Pack()
				require.NoError(t, err)
				options.DNSCache = func() adapter.DNSCacheStore { return &corruptDNSCacheStore{rawMessage: packed} }
			}
			client := NewClient(options)
			client.Start()
			keys := []dnsCacheKey{
				{Question: msg.Question[0], transportTag: "a"},
				{Question: msg.Question[0], transportTag: "b"},
				{Question: msg.Question[0], transportTag: "a", clientSubnet: netip.MustParsePrefix("192.0.2.0/24")},
				{Question: msg.Question[0], transportTag: "a", environment: 1},
			}
			for _, key := range keys {
				client.storeCache(key, msg, 300)
			}
			for _, key := range keys {
				first, _, _ := client.loadResponse(key)
				second, _, _ := client.loadResponse(key)
				require.Equal(t, "192.0.2.2", MessageToAddresses(first)[0].Unmap().String())
				require.Equal(t, "192.0.2.1", MessageToAddresses(second)[0].Unmap().String())
				require.Equal(t, "2001:db8::2", MessageToAddresses(first)[2].String())
				require.Equal(t, "2001:db8::1", MessageToAddresses(second)[2].String())
				require.IsType(t, &mDNS.CNAME{}, first.Answer[0])
			}
			var counts [2]atomic.Int32
			var wg sync.WaitGroup
			for range 100 {
				wg.Go(func() {
					response, _, _ := client.loadResponse(keys[0])
					if MessageToAddresses(response)[0].Unmap().String() == "192.0.2.1" {
						counts[0].Add(1)
					} else {
						counts[1].Add(1)
					}
				})
			}
			wg.Wait()
			require.EqualValues(t, 50, counts[0].Load())
			require.EqualValues(t, 50, counts[1].Load())
			require.Equal(t, original, msg.String())
			client.ClearCache()
			if persistent {
				require.Zero(t, client.roundRobinIndex.Len())
			} else {
				response, _, _ := client.loadResponse(keys[0])
				require.Nil(t, response)
			}
		})
	}
}

func TestRoundRobinCounterWrap(t *testing.T) {
	var index atomic.Uint32
	index.Store(^uint32(0))
	require.Less(t, nextRotation(&index, 3), uint32(3))
	require.Equal(t, []int{1}, reverseRotateSlice([]int{1}, 1))
	require.Empty(t, reverseRotateSlice([]int{}, 1))
}
