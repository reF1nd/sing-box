package dns

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"sync/atomic"
	"testing"
	"testing/synctest"
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
	message *mDNS.Msg
	result  chan dedupResult
}

func (q dedupQuery) reply(address netip.Addr) {
	q.result <- dedupResult{response: FixedResponse(q.message.Id, q.message.Question[0], []netip.Addr{address}, 60)}
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
	t.queries <- dedupQuery{message.Copy(), result}
	select {
	case r := <-result:
		return r.response, r.err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (t *dedupTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	go func() {
		callback(t.Exchange(ctx, message))
	}()
}

func dedupQuestion(id uint16) *mDNS.Msg {
	message := new(mDNS.Msg)
	message.SetQuestion("dedup.example.", mDNS.TypeA)
	message.Id = id
	return message
}

// Called inside a synctest bubble so every waiter is blocked before the test proceeds.
func startDedupExchange(ctx context.Context, client *Client, transport *dedupTransport, id uint16, options adapter.DNSQueryOptions, async bool) <-chan dedupResult {
	result := make(chan dedupResult, 1)
	callback := func(response *mDNS.Msg, err error) { result <- dedupResult{response, err} }
	if async {
		client.ExchangeAsync(ctx, transport, dedupQuestion(id), options, nil, callback)
	} else {
		go func() {
			callback(client.Exchange(ctx, transport, dedupQuestion(id), options, nil))
		}()
	}
	synctest.Wait()
	return result
}

func receiveDedup[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case value := <-ch:
		return value
	default:
		t.Fatal("expected DNS query or result")
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
					synctest.Test(t, func(t *testing.T) {
						ctx, cancel := context.WithCancel(t.Context())
						defer cancel()
						client := NewClient(ClientOptions{Context: ctx})
						transport := &dedupTransport{queries: make(chan dedupQuery, 8)}
						transport.environment.Store(1)
						options := adapter.DNSQueryOptions{}
						leader := startDedupExchange(ctx, client, transport, 1, options, true)
						oldQuery := receiveDedup(t, transport.queries)
						var waiters []<-chan dedupResult
						for id := uint16(2); id < 5; id++ {
							waiters = append(waiters, startDedupExchange(ctx, client, transport, id, options, async))
						}
						require.Empty(t, transport.queries, "waiters must join the original query")

						changed := scenario != "unchanged"
						if changed {
							transport.environment.Store(2)
						}
						var newLeader <-chan dedupResult
						var newQuery dedupQuery
						if scenario == "changed with pending query" {
							newLeader = startDedupExchange(ctx, client, transport, 5, options, true)
							newQuery = receiveDedup(t, transport.queries)
						}
						oldAddress := netip.MustParseAddr("192.0.2.1")
						newAddress := netip.MustParseAddr("192.0.2.2")
						failure := errors.New("old resolver failed")
						if failed {
							oldQuery.result <- dedupResult{err: failure}
						} else {
							oldQuery.reply(oldAddress)
						}
						synctest.Wait()
						first := receiveDedup(t, leader)
						if failed {
							require.ErrorIs(t, first.err, failure)
						} else {
							require.NoError(t, first.err)
						}
						if changed {
							key := client.newCacheKey(transport, oldQuery.message.Question[0], oldQuery.message, options)
							cached, _, _ := client.loadResponse(key)
							require.Nil(t, cached, "old answer must not populate the new environment's cache")
						}
						if changed || failed {
							if newLeader == nil {
								newQuery = receiveDedup(t, transport.queries)
							}
							require.Empty(t, transport.queries, "waiters must share one query after waking")
							newQuery.reply(newAddress)
							synctest.Wait()
							if newLeader != nil {
								require.NoError(t, receiveDedup(t, newLeader).err)
							}
						}
						for i, waiter := range waiters {
							result := receiveDedup(t, waiter)
							require.NoError(t, result.err)
							require.NotNil(t, result.response)
							require.Equal(t, uint16(i+2), result.response.Id)
							expected := oldAddress
							if changed || failed {
								expected = newAddress
							}
							require.Equal(t, []netip.Addr{expected}, MessageToAddresses(result.response))
						}
						require.Empty(t, transport.queries)
						require.Zero(t, client.cacheLock.Len(), "completed queries must release their locks")
					})
				})
			}
		}
	}
}

func TestExchangeDedupWaitCancellation(t *testing.T) {
	for _, async := range []bool{false, true} {
		for _, timeout := range []bool{false, true} {
			t.Run("async="+strconv.FormatBool(async)+"/timeout="+strconv.FormatBool(timeout), func(t *testing.T) {
				synctest.Test(t, func(t *testing.T) {
					ctx, cancel := context.WithCancel(t.Context())
					defer cancel()
					client := NewClient(ClientOptions{Context: ctx})
					transport := &dedupTransport{queries: make(chan dedupQuery, 8)}
					transport.environment.Store(1)
					options := adapter.DNSQueryOptions{Timeout: time.Second}
					leader := startDedupExchange(ctx, client, transport, 1, options, true)
					oldQuery := receiveDedup(t, transport.queries)
					waitCtx, cancelWait := context.WithTimeout(ctx, 100*time.Millisecond)
					defer cancelWait()
					waiter := startDedupExchange(waitCtx, client, transport, 2, options, async)
					transport.environment.Store(2)
					newLeader := startDedupExchange(ctx, client, transport, 3, options, true)
					newQuery := receiveDedup(t, transport.queries)
					time.Sleep(40 * time.Millisecond)
					oldQuery.reply(netip.MustParseAddr("192.0.2.1"))
					synctest.Wait()
					require.NoError(t, receiveDedup(t, leader).err)
					require.Empty(t, transport.queries, "waiter must join the new environment's query")
					expectedErr := context.Canceled
					if timeout {
						time.Sleep(60 * time.Millisecond)
						expectedErr = context.DeadlineExceeded
					} else {
						cancelWait()
					}
					synctest.Wait()
					require.ErrorIs(t, receiveDedup(t, waiter).err, expectedErr)
					require.Equal(t, 1, client.cacheLock.Len(), "canceled waiter must not release another query's lock")
					survivor := startDedupExchange(ctx, client, transport, 4, options, async)
					require.Empty(t, transport.queries)
					newQuery.reply(netip.MustParseAddr("192.0.2.2"))
					synctest.Wait()
					require.NoError(t, receiveDedup(t, newLeader).err)
					require.NoError(t, receiveDedup(t, survivor).err)
					require.Zero(t, client.cacheLock.Len())
				})
			})
		}
	}
}

func TestExchangeDedupTimeoutPartition(t *testing.T) {
	for _, async := range []bool{false, true} {
		t.Run("async="+strconv.FormatBool(async), func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				ctx, cancel := context.WithCancel(t.Context())
				defer cancel()
				client := NewClient(ClientOptions{Context: ctx})
				transport := &dedupTransport{queries: make(chan dedupQuery, 8)}
				long := startDedupExchange(ctx, client, transport, 1, adapter.DNSQueryOptions{Timeout: time.Second}, true)
				longQuery := receiveDedup(t, transport.queries)
				short := startDedupExchange(ctx, client, transport, 2, adapter.DNSQueryOptions{Timeout: 100 * time.Millisecond}, async)
				receiveDedup(t, transport.queries)
				time.Sleep(100 * time.Millisecond)
				synctest.Wait()
				require.ErrorIs(t, receiveDedup(t, short).err, context.DeadlineExceeded)
				require.Equal(t, 1, client.cacheLock.Len())
				longQuery.reply(netip.MustParseAddr("192.0.2.1"))
				synctest.Wait()
				require.NoError(t, receiveDedup(t, long).err)
				require.Zero(t, client.cacheLock.Len())
			})
		})
	}
}
