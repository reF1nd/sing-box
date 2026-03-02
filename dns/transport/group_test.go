package transport

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

type groupTestManager struct {
	adapter.DNSTransportManager
	transports map[string]adapter.DNSTransport
}

func (m groupTestManager) Transport(tag string) (adapter.DNSTransport, bool) {
	t, ok := m.transports[tag]
	return t, ok
}

type groupTestTransport struct {
	adapter.DNSTransport
	exchange func(context.Context, *mDNS.Msg, func(*mDNS.Msg, error))
}

func (t groupTestTransport) ExchangeAsync(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	t.exchange(ctx, message, callback)
}

func newTestGroup(t *testing.T, transports map[string]adapter.DNSTransport, tags ...string) adapter.DNSTransport {
	t.Helper()
	ctx := service.ContextWith[adapter.DNSTransportManager](context.Background(), groupTestManager{transports: transports})
	group, err := NewGroup(ctx, log.NewNOPFactory().Logger(), "group", option.GroupDNSServerOptions{Servers: tags})
	if err != nil {
		t.Fatal(err)
	}
	return group
}

func TestGroupConcurrentSynchronousTransports(t *testing.T) {
	slowStarted := make(chan struct{})
	slowDone := make(chan struct{})
	parent := &adapter.InboundContext{Domain: "original.example"}
	request := new(mDNS.Msg).SetQuestion("original.example.", mDNS.TypeA)
	group := newTestGroup(t, map[string]adapter.DNSTransport{
		"slow": groupTestTransport{exchange: func(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
			adapter.ContextFrom(ctx).Domain = "slow.example"
			message.Question[0].Name = "slow.example."
			close(slowStarted)
			<-ctx.Done()
			callback(nil, ctx.Err())
			close(slowDone)
		}},
		"fast": groupTestTransport{exchange: func(ctx context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
			<-slowStarted
			if adapter.ContextFrom(ctx).Domain != parent.Domain || message.Question[0].Name != request.Question[0].Name {
				t.Error("child request state leaked across transports")
			}
			callback(new(mDNS.Msg).SetReply(message), nil)
		}},
	}, "slow", "fast")
	ctx, cancel := context.WithTimeout(adapter.WithContext(context.Background(), parent), time.Second)
	defer cancel()
	response, err := group.Exchange(ctx, request)
	if err != nil || response == nil {
		t.Fatalf("fast response: %v, %v", response, err)
	}
	<-slowDone
	if parent.Domain != "original.example" || request.Question[0].Name != "original.example." {
		t.Fatal("group modified caller state")
	}
}

func TestGroupCancellationWithoutMemberCallback(t *testing.T) {
	group := newTestGroup(t, map[string]adapter.DNSTransport{
		"silent": groupTestTransport{exchange: func(context.Context, *mDNS.Msg, func(*mDNS.Msg, error)) {}},
	}, "silent")
	ctx, cancel := context.WithCancel(context.Background())
	var calls atomic.Int32
	done := make(chan error, 2)
	group.ExchangeAsync(ctx, new(mDNS.Msg), func(_ *mDNS.Msg, err error) {
		calls.Add(1)
		done <- err
	})
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("group did not honor cancellation")
	}
	if calls.Load() != 1 {
		t.Fatal("callback invoked more than once")
	}
}

func TestGroupSkipsFailedMembers(t *testing.T) {
	memberErr := errors.New("member failed")
	for _, success := range []bool{false, true} {
		group := newTestGroup(t, map[string]adapter.DNSTransport{
			"failed": groupTestTransport{exchange: func(_ context.Context, _ *mDNS.Msg, callback func(*mDNS.Msg, error)) {
				callback(nil, memberErr)
			}},
			"last": groupTestTransport{exchange: func(_ context.Context, message *mDNS.Msg, callback func(*mDNS.Msg, error)) {
				if success {
					callback(new(mDNS.Msg).SetReply(message), nil)
				} else {
					callback(nil, memberErr)
				}
			}},
		}, "failed", "last")
		response, err := group.Exchange(context.Background(), new(mDNS.Msg))
		if success && (err != nil || response == nil) || !success && !errors.Is(err, memberErr) {
			t.Fatalf("success=%v: response=%v, err=%v", success, response, err)
		}
	}
}
