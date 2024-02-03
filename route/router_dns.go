package route

import (
	"context"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-dns"
	"github.com/sagernet/sing/common/cache"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"

	mDNS "github.com/miekg/dns"
)

type DNSReverseMapping struct {
	cache *cache.LruCache[netip.Addr, string]
}

func NewDNSReverseMapping() *DNSReverseMapping {
	return &DNSReverseMapping{
		cache: cache.New[netip.Addr, string](),
	}
}

func (m *DNSReverseMapping) Save(address netip.Addr, domain string, ttl int) {
	m.cache.StoreWithExpire(address, domain, time.Now().Add(time.Duration(ttl)*time.Second))
}

func (m *DNSReverseMapping) Query(address netip.Addr) (string, bool) {
	domain, loaded := m.cache.Load(address)
	return domain, loaded
}

func (r *Router) lookupDomain(ctx context.Context, domain string, transport dns.Transport, strategy dns.DomainStrategy) ([]netip.Addr, error) {
	ctx, cancel := context.WithTimeout(ctx, C.DNSTimeout)
	defer cancel()
	addrs, err := r.dnsClient.Lookup(ctx, transport, domain, strategy)
	if len(addrs) > 0 {
		r.dnsLogger.InfoContext(ctx, "lookup succeed for ", domain, ": ", strings.Join(F.MapToString(addrs), " "))
	} else if err != nil {
		r.dnsLogger.ErrorContext(ctx, E.Cause(err, "lookup failed for ", domain))
	} else {
		r.dnsLogger.ErrorContext(ctx, "lookup failed for ", domain, ": empty result")
		err = dns.RCodeNameError
	}
	return addrs, err
}

func buildFallbackMetadata(addresses []netip.Addr) *adapter.InboundContext {
	return &adapter.InboundContext{
		Destination: M.Socksaddr{
			Fqdn: "a.b.c",
			Port: 80,
		},
		DestinationAddresses: addresses,
		DnsFallBack:          true,
	}
}

func (r *Router) getRequest(ctx context.Context, transport dns.Transport, message *mDNS.Msg, strategy dns.DomainStrategy) (*mDNS.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, C.DNSTimeout)
	defer cancel()
	msg, err := r.dnsClient.Exchange(ctx, transport, message, strategy)
	return msg, err
}

func (r *Router) matchDNS0(ctx context.Context, fStrategy dns.DomainStrategy) ([]netip.Addr, error) {
	var strategy uint8
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil {
		panic("no context")
	}
	defer metadata.ResetRuleCache()
	for i, rule := range r.dnsRules {
		metadata.ResetRuleCache()
		if rule.Match(metadata) {
			detour := rule.Outbound()
			transport, loaded := r.transportMap[detour]
			if !loaded {
				r.dnsLogger.ErrorContext(ctx, "transport not found: ", detour)
				continue
			}
			if _, isFakeIP := transport.(adapter.FakeIPTransport); isFakeIP {
				continue
			}
			r.dnsLogger.DebugContext(ctx, "match[", i, "] ", rule.String(), " => ", detour)
			if rule.DisableCache() {
				ctx = dns.ContextWithDisableCache(ctx, true)
			}
			if rewriteTTL := rule.RewriteTTL(); rewriteTTL != nil {
				ctx = dns.ContextWithRewriteTTL(ctx, *rewriteTTL)
			}
			strategy = r.defaultDomainStrategy
			if domainStrategy, dsLoaded := r.transportDomainStrategy[transport]; dsLoaded {
				strategy = domainStrategy
			}
			if fStrategy != dns.DomainStrategyAsIS {
				strategy = fStrategy
			}
			addrs, err := r.lookupDomain(ctx, metadata.Domain, transport, strategy)
			if len(addrs) > 0 && rule.MatchFallback(buildFallbackMetadata(addrs)) {
				r.dnsLogger.DebugContext(ctx, "match fallback, continue")
				continue
			}
			return addrs, err
		}
	}
	strategy = r.defaultDomainStrategy
	if domainStrategy, dsLoaded := r.transportDomainStrategy[r.defaultTransport]; dsLoaded {
		strategy = domainStrategy
	}
	if fStrategy != dns.DomainStrategyAsIS {
		strategy = fStrategy
	}
	return r.lookupDomain(ctx, metadata.Domain, r.defaultTransport, strategy)
}

func (r *Router) matchDNS1(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil {
		panic("no context")
	}
	for i, rule := range r.dnsRules {
		metadata.ResetRuleCache()
		if rule.Match(metadata) {
			detour := rule.Outbound()
			transport, loaded := r.transportMap[detour]
			if !loaded {
				r.dnsLogger.ErrorContext(ctx, "transport not found: ", detour)
				continue
			}
			r.dnsLogger.DebugContext(ctx, "match[", i, "] ", rule.String(), " => ", detour)
			if rule.DisableCache() {
				ctx = dns.ContextWithDisableCache(ctx, true)
			}
			if rewriteTTL := rule.RewriteTTL(); rewriteTTL != nil {
				ctx = dns.ContextWithRewriteTTL(ctx, *rewriteTTL)
			}
			strategy := r.defaultDomainStrategy
			if domainStrategy, dsLoaded := r.transportDomainStrategy[transport]; dsLoaded {
				strategy = domainStrategy
			}
			response, err := r.getRequest(ctx, transport, message, strategy)
			if err != nil || response == nil {
				return response, err
			}
			var addrs []netip.Addr
			for _, answer := range response.Answer {
				switch record := answer.(type) {
				case *mDNS.A:
					addrs = append(addrs, M.AddrFromIP(record.A))
				case *mDNS.AAAA:
					addrs = append(addrs, M.AddrFromIP(record.AAAA))
				}
			}
			if len(addrs) > 0 && rule.MatchFallback(buildFallbackMetadata(addrs)) {
				r.dnsLogger.DebugContext(ctx, "match fallback, continue")
				continue
			}
			return response, err
		}
	}
	strategy := r.defaultDomainStrategy
	if domainStrategy, dsLoaded := r.transportDomainStrategy[r.defaultTransport]; dsLoaded {
		strategy = domainStrategy
	}
	return r.getRequest(ctx, r.defaultTransport, message, strategy)
}

func (r *Router) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if len(message.Question) > 0 {
		r.dnsLogger.DebugContext(ctx, "exchange ", formatQuestion(message.Question[0].String()))
	}
	var (
		response *mDNS.Msg
		cached   bool
		err      error
	)
	response, cached = r.dnsClient.ExchangeCache(ctx, message)
	if !cached {
		ctx, metadata := adapter.AppendContext(ctx)
		if len(message.Question) > 0 {
			metadata.QueryType = message.Question[0].Qtype
			switch metadata.QueryType {
			case mDNS.TypeA:
				metadata.IPVersion = 4
			case mDNS.TypeAAAA:
				metadata.IPVersion = 6
			}
			metadata.Domain = fqdnToDomain(message.Question[0].Name)
		}
		response, err = r.matchDNS1(ctx, message)
		if err != nil && len(message.Question) > 0 {
			r.dnsLogger.ErrorContext(ctx, E.Cause(err, "exchange failed for ", formatQuestion(message.Question[0].String())))
		}
	}
	if len(message.Question) > 0 && response != nil {
		LogDNSAnswers(r.dnsLogger, ctx, message.Question[0].Name, response.Answer)
	}
	if r.dnsReverseMapping != nil && len(message.Question) > 0 && response != nil && len(response.Answer) > 0 {
		for _, answer := range response.Answer {
			switch record := answer.(type) {
			case *mDNS.A:
				r.dnsReverseMapping.Save(M.AddrFromIP(record.A), fqdnToDomain(record.Hdr.Name), int(record.Hdr.Ttl))
			case *mDNS.AAAA:
				r.dnsReverseMapping.Save(M.AddrFromIP(record.AAAA), fqdnToDomain(record.Hdr.Name), int(record.Hdr.Ttl))
			}
		}
	}
	return response, err
}

func (r *Router) Lookup(ctx context.Context, domain string, strategy dns.DomainStrategy) ([]netip.Addr, error) {
	r.dnsLogger.DebugContext(ctx, "lookup domain ", domain)
	ctx, metadata := adapter.AppendContext(ctx)
	metadata.Domain = domain
	return r.matchDNS0(ctx, strategy)
}

func (r *Router) LookupDefault(ctx context.Context, domain string) ([]netip.Addr, error) {
	return r.Lookup(ctx, domain, dns.DomainStrategyAsIS)
}

func (r *Router) ClearDNSCache() {
	r.dnsClient.ClearCache()
	if r.platformInterface != nil {
		r.platformInterface.ClearDNSCache()
	}
}

func LogDNSAnswers(logger log.ContextLogger, ctx context.Context, domain string, answers []mDNS.RR) {
	for _, answer := range answers {
		logger.InfoContext(ctx, "exchanged ", domain, " ", mDNS.Type(answer.Header().Rrtype).String(), " ", formatQuestion(answer.String()))
	}
}

func fqdnToDomain(fqdn string) string {
	if mDNS.IsFqdn(fqdn) {
		return fqdn[:len(fqdn)-1]
	}
	return fqdn
}

func formatQuestion(string string) string {
	if strings.HasPrefix(string, ";") {
		string = string[1:]
	}
	string = strings.ReplaceAll(string, "\t", " ")
	for strings.Contains(string, "  ") {
		string = strings.ReplaceAll(string, "  ", " ")
	}
	return string
}
