package dns

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"

	mDNS "github.com/miekg/dns"
	"github.com/stretchr/testify/require"
)

type dedupResult struct {
	response *mDNS.Msg
	err      error
}

type dedupQuery struct {
	message  *mDNS.Msg
	complete func(*mDNS.Msg, error)
}

type dedupTransport struct {
	adapter.DNSTransport
	environment atomic.Uint32
	queries     chan dedupQuery
}

func (t *dedupTransport) Tag() string { return "dedup" }

func (t *dedupTransport) Environment() []string {
	return []string{strconv.FormatUint(uint64(t.environment.Load()), 10)}
}

func (t *dedupTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	result := make(chan dedupResult, 1)
	t.ExchangeAsync(ctx, message, func(response *mDNS.Msg, err error) {
		result <- dedupResult{response, err}
	})
	select {
	case r := <-result:
		return r.response, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *dedupTransport) ExchangeAsync(_ context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	t.queries <- dedupQuery{message.Copy(), callback}
}

// Done is evaluated by beginExchange's wait select after it joins the pending query.
// This lets the synchronous test wait for registration without timing sleeps.
type dedupWaitContext struct {
	context.Context
	waiting chan struct{}
	once    sync.Once
}

func (c *dedupWaitContext) Done() <-chan struct{} {
	c.once.Do(func() { close(c.waiting) })
	return c.Context.Done()
}

func dedupQuestion(id uint16) *mDNS.Msg {
	message := new(mDNS.Msg)
	message.SetQuestion("dedup.example.", mDNS.TypeA)
	message.Id = id
	return message
}

func receiveDedup[T any](t *testing.T, ctx context.Context, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	case <-ctx.Done():
		t.Fatal("DNS exchange did not complete: ", ctx.Err())
		var zero T
		return zero
	}
}

func TestExchangeDedupEnvironment(t *testing.T) {
	for _, async := range []bool{false, true} {
		for _, failed := range []bool{false, true} {
			for _, scenario := range []string{"unchanged", "changed", "changed with pending query"} {
				name := scenario + "/async=" + strconv.FormatBool(async) + "/failed=" + strconv.FormatBool(failed)
				t.Run(name, func(t *testing.T) {
					ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
					defer cancel()
					client := NewClient(ClientOptions{Context: ctx})
					transport := &dedupTransport{queries: make(chan dedupQuery, 8)}
					transport.environment.Store(1)
					options := adapter.DNSQueryOptions{}
					startAsync := func(id uint16) <-chan dedupResult {
						result := make(chan dedupResult, 1)
						client.ExchangeAsync(ctx, transport, dedupQuestion(id), options, nil, func(response *mDNS.Msg, err error) {
							result <- dedupResult{response, err}
						})
						return result
					}
					leader := startAsync(1)
					query := receiveDedup(t, ctx, transport.queries)
					var waiter <-chan dedupResult
					if async {
						waiter = startAsync(2)
					} else {
						result := make(chan dedupResult, 1)
						waiter = result
						waitCtx := &dedupWaitContext{Context: ctx, waiting: make(chan struct{})}
						go func() {
							response, err := client.Exchange(waitCtx, transport, dedupQuestion(2), options, nil)
							result <- dedupResult{response, err}
						}()
						receiveDedup(t, ctx, waitCtx.waiting)
					}
					require.Empty(t, transport.queries, "waiter must join the first query")

					changed := scenario != "unchanged"
					if changed {
						transport.environment.Store(2)
					}
					var newLeader <-chan dedupResult
					var newQuery dedupQuery
					if scenario == "changed with pending query" {
						newLeader = startAsync(3)
						newQuery = receiveDedup(t, ctx, transport.queries)
					}
					oldAddress := netip.MustParseAddr("192.0.2.1")
					newAddress := netip.MustParseAddr("192.0.2.2")
					failure := errors.New("old resolver failed")
					if failed {
						query.complete(nil, failure)
					} else {
						query.complete(FixedResponse(query.message.Id, query.message.Question[0], []netip.Addr{oldAddress}, 60), nil)
					}
					firstResult := receiveDedup(t, ctx, leader)
					if failed {
						require.ErrorIs(t, firstResult.err, failure)
					} else {
						require.NoError(t, firstResult.err)
					}

					if changed {
						key := client.newCacheKey(transport, query.message.Question[0], query.message, options)
						cached, _, _ := client.loadResponse(key)
						require.Nil(t, cached, "old answer must not populate the new environment's cache")
						if newLeader == nil {
							newQuery = receiveDedup(t, ctx, transport.queries)
						}
						newQuery.complete(FixedResponse(newQuery.message.Id, newQuery.message.Question[0], []netip.Addr{newAddress}, 60), nil)
						if newLeader != nil {
							require.NoError(t, receiveDedup(t, ctx, newLeader).err)
						}
					}
					result := receiveDedup(t, ctx, waiter)
					if failed && !changed {
						require.ErrorIs(t, result.err, failure)
					} else {
						require.NoError(t, result.err)
						require.NotNil(t, result.response)
						require.Equal(t, uint16(2), result.response.Id)
						expected := oldAddress
						if changed {
							expected = newAddress
						}
						require.Equal(t, []netip.Addr{expected}, MessageToAddresses(result.response))
					}
					require.Empty(t, transport.queries, "retries must reuse a pending or cached query in the new environment")
				})
			}
		}
	}
}
