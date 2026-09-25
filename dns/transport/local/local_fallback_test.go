package local

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/dns/transport/local/systemconfig"
	"github.com/sagernet/sing-box/log"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	mDNS "github.com/miekg/dns"
)

type fallbackTestConfig struct{ config *systemconfig.Config }

func (s *fallbackTestConfig) Configuration() *systemconfig.Config { return s.config }
func (*fallbackTestConfig) Reset()                                {}
func (*fallbackTestConfig) Close() error                          { return nil }

type fallbackTestResolver struct {
	ResolvedResolver
	err      error
	response *mDNS.Msg
	fallback bool
	calls    atomic.Int32
}

func (r *fallbackTestResolver) Fallback() bool        { return r.fallback }
func (r *fallbackTestResolver) Environment() []string { return []string{"resolved-test"} }
func (r *fallbackTestResolver) Close() error          { return nil }
func (r *fallbackTestResolver) ExchangeAsync(_ context.Context, _ *mDNS.Msg, callback func(*mDNS.Msg, error)) {
	r.calls.Add(1)
	callback(r.response, r.err)
}

func fallbackTestServer(t *testing.T) (M.Socksaddr, *atomic.Int32) {
	t.Helper()
	conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	calls := new(atomic.Int32)
	server := &mDNS.Server{PacketConn: conn, Handler: mDNS.HandlerFunc(func(w mDNS.ResponseWriter, q *mDNS.Msg) {
		calls.Add(1)
		response := new(mDNS.Msg).SetReply(q)
		switch q.Question[0].Qtype {
		case mDNS.TypeA:
			response.Answer = []mDNS.RR{&mDNS.A{Hdr: mDNS.RR_Header{Name: q.Question[0].Name, Rrtype: mDNS.TypeA, Class: mDNS.ClassINET, Ttl: 60}, A: net.ParseIP("192.0.2.1")}}
		case mDNS.TypeAAAA:
			response.Answer = []mDNS.RR{&mDNS.AAAA{Hdr: mDNS.RR_Header{Name: q.Question[0].Name, Rrtype: mDNS.TypeAAAA, Class: mDNS.ClassINET, Ttl: 60}, AAAA: net.ParseIP("2001:db8::1")}}
		}
		_ = w.WriteMsg(response)
	})}
	ready := make(chan struct{})
	server.NotifyStartedFunc = func() { close(ready) }
	go func() { _ = server.ActivateAndServe() }()
	<-ready
	t.Cleanup(func() { _ = server.Shutdown() })
	return M.SocksaddrFromNet(conn.LocalAddr()), calls
}

func fallbackTestTransport(t *testing.T, resolver ResolvedResolver, destination M.Socksaddr) *Transport {
	t.Helper()
	transport := &Transport{
		ctx: context.Background(), logger: log.NewNOPFactory().Logger(),
		preferredResolver: &PreferredDomainResolver{}, resolved: resolver, dialer: N.SystemDialer,
		configSource: &fallbackTestConfig{&systemconfig.Config{Servers: []M.Socksaddr{destination}, Ndots: 1, Attempts: 1, Timeout: time.Second}},
	}
	t.Cleanup(func() { _ = transport.Close() })
	return transport
}

func TestLocalResolvedFallback(t *testing.T) {
	destination, calls := fallbackTestServer(t)
	resolver := &fallbackTestResolver{err: fmt.Errorf("wrapped: %w", errResolvedUnavailable), fallback: true}
	transport := fallbackTestTransport(t, resolver, destination)
	initial := transport.Environment()
	if initial[0] != "resolv.conf" {
		t.Fatal(initial)
	}
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			qtype := uint16(mDNS.TypeA)
			if i%2 != 0 {
				qtype = mDNS.TypeAAAA
			}
			query := new(mDNS.Msg).SetQuestion("fallback.example.", qtype)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			response, err := transport.Exchange(ctx, query)
			if err != nil {
				t.Error(err)
				return
			}
			if response.Id != query.Id || len(response.Answer) != 1 || response.Answer[0].Header().Rrtype != qtype {
				t.Errorf("invalid response: %v", response)
			}
		}(i)
	}
	wg.Wait()
	if calls.Load() != 32 {
		t.Fatalf("fallback queries=%d", calls.Load())
	}
	resolver.fallback = false
	if slices.Equal(initial, transport.Environment()) {
		t.Fatal("backend change did not change environment")
	}
	resolver.fallback = true
	transport.configSource.(*fallbackTestConfig).config = &systemconfig.Config{Servers: []M.Socksaddr{M.SocksaddrFrom(netip.MustParseAddr("192.0.2.53"), 53)}}
	if slices.Equal(initial, transport.Environment()) {
		t.Fatal("nameserver change did not change environment")
	}
}

func TestLocalResolvedDoesNotFallbackOnQueryFailure(t *testing.T) {
	destination, calls := fallbackTestServer(t)
	query := new(mDNS.Msg).SetQuestion("failure.example.", mDNS.TypeA)
	for _, queryErr := range []error{errors.New("DNS query failed"), context.DeadlineExceeded, context.Canceled} {
		resolver := &fallbackTestResolver{err: queryErr}
		transport := fallbackTestTransport(t, resolver, destination)
		_, err := transport.Exchange(context.Background(), query)
		if !errors.Is(err, queryErr) {
			t.Fatalf("got %v want %v", err, queryErr)
		}
	}
	for _, rcode := range []int{mDNS.RcodeSuccess, mDNS.RcodeNameError, mDNS.RcodeServerFailure} {
		response := new(mDNS.Msg).SetRcode(query, rcode)
		transport := fallbackTestTransport(t, &fallbackTestResolver{response: response}, destination)
		got, err := transport.Exchange(context.Background(), query)
		if err != nil || got.Rcode != rcode {
			t.Fatalf("rcode=%d response=%v error=%v", rcode, got, err)
		}
	}
	resolver := &fallbackTestResolver{err: errResolvedUnavailable, fallback: true}
	transport := fallbackTestTransport(t, resolver, destination)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := transport.Exchange(ctx, query)
	if !errors.Is(err, context.Canceled) || resolver.calls.Load() != 0 {
		t.Fatalf("cancel: %v calls=%d", err, resolver.calls.Load())
	}
	if calls.Load() != 0 {
		t.Fatalf("unexpected fallback queries=%d", calls.Load())
	}
}
