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

func (r *Router) lookupMulitServer(ctx context.Context, domain string, transports []dns.Transport, fStrategy dns.DomainStrategy) ([]netip.Addr, error) {
	length := len(transports)
	addrsChan := make(chan []netip.Addr, length)
	errChan := make(chan error, length)
	for _, transport := range transports {
		strategy := r.defaultDomainStrategy
		if domainStrategy, dsLoaded := r.transportDomainStrategy[transport]; dsLoaded {
			strategy = domainStrategy
		}
		if fStrategy != dns.DomainStrategyAsIS {
			strategy = fStrategy
		}
		go func(transport dns.Transport, strategy dns.DomainStrategy) {
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
			addrsChan <- addrs
			errChan <- err
		}(transport, strategy)
	}
	var err error
	for i := 0; i < length; i++ {
		addrs := <-addrsChan
		errr := <-errChan
		if len(addrs) > 0 {
			return addrs, errr
		}
		if errr != context.DeadlineExceeded || err == nil {
			err = errr
		}
		if errr == context.DeadlineExceeded {
			break
		}
	}
	return nil, err
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

func (r *Router) getRequestMulitServer(ctx context.Context, transports []dns.Transport, message *mDNS.Msg) (*mDNS.Msg, error) {
	length := len(transports)
	resChan := make(chan *mDNS.Msg, length)
	errChan := make(chan error, length)
	for _, transport := range transports {
		strategy := r.defaultDomainStrategy
		if domainStrategy, dsLoaded := r.transportDomainStrategy[transport]; dsLoaded {
			strategy = domainStrategy
		}
		go func(transport dns.Transport, strategy dns.DomainStrategy) {
			ctx, cancel := context.WithTimeout(ctx, C.DNSTimeout)
			defer cancel()
			response, err := r.dnsClient.Exchange(ctx, transport, message, strategy)
			if err != nil && len(message.Question) > 0 {
				r.dnsLogger.ErrorContext(ctx, E.Cause(err, "exchange failed for ", formatQuestion(message.Question[0].String())))
			}
			if len(message.Question) > 0 && response != nil {
				LogDNSAnswers(r.dnsLogger, ctx, message.Question[0].Name, response.Answer)
			}
			resChan <- response
			errChan <- err
		}(transport, strategy)
	}
	var response *mDNS.Msg
	var err error
	for i := 0; i < length; i++ {
		resp := <-resChan
		errr := <-errChan
		if errr != context.DeadlineExceeded || err == nil {
			response = resp
			err = errr
		}
		if errr == context.DeadlineExceeded {
			break
		}
		if err == nil && response != nil && len(response.Answer) > 0 {
			break
		}
	}
	return response, err
}

func (r *Router) matchDNS0(ctx context.Context, fStrategy dns.DomainStrategy) ([]netip.Addr, error) {
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil {
		panic("no context")
	}
	defer metadata.ResetRuleCache()
	for i, rule := range r.dnsRules {
		metadata.ResetRuleCache()
		if rule.Match(metadata) {
			var transports []dns.Transport
			servers := rule.Servers()
			for _, server := range servers {
				transport := r.transportMap[server]
				transports = append(transports, transport)
			}
			if _, isFakeIP := transports[0].(adapter.FakeIPTransport); isFakeIP {
				continue
			}
			targetServer := servers[0]
			if len(servers) > 1 {
				targetServer = "[" + strings.Join(servers, ", ") + "]"
			}
			r.dnsLogger.DebugContext(ctx, "match[", i, "] ", rule.String(), " => ", targetServer)
			if rule.DisableCache() {
				ctx = dns.ContextWithDisableCache(ctx, true)
			}
			if rewriteTTL := rule.RewriteTTL(); rewriteTTL != nil {
				ctx = dns.ContextWithRewriteTTL(ctx, *rewriteTTL)
			}
			addrs, err := r.lookupMulitServer(ctx, metadata.Domain, transports, fStrategy)
			if continued := func() bool {
				if err != nil || len(addrs) == 0 {
					return false
				}
				return rule.MatchFallback(buildFallbackMetadata(addrs))
			}(); continued {
				r.dnsLogger.DebugContext(ctx, "match fallback, continue")
				continue
			}
			return addrs, err
		}
	}
	return r.lookupMulitServer(ctx, metadata.Domain, r.defaultTransports, fStrategy)
}

func (r *Router) matchDNS1(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, bool, error) {
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil {
		panic("no context")
	}
	for i, rule := range r.dnsRules {
		metadata.ResetRuleCache()
		if rule.Match(metadata) {
			var isFakeIP bool
			var transports []dns.Transport
			servers := rule.Servers()
			for _, server := range servers {
				transport := r.transportMap[server]
				transports = append(transports, transport)
				_, isFakeIP = transport.(adapter.FakeIPTransport)
			}
			targetServer := servers[0]
			if len(servers) > 1 {
				targetServer = "[" + strings.Join(servers, ", ") + "]"
			}
			r.dnsLogger.DebugContext(ctx, "match[", i, "] ", rule.String(), " => ", targetServer)
			if rule.DisableCache() {
				ctx = dns.ContextWithDisableCache(ctx, true)
			}
			if rewriteTTL := rule.RewriteTTL(); rewriteTTL != nil {
				ctx = dns.ContextWithRewriteTTL(ctx, *rewriteTTL)
			}
			response, err := r.getRequestMulitServer(ctx, transports, message)
			if fallback := func() bool {
				if err != nil || response == nil || len(response.Answer) == 0 {
					return false
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
				return len(addrs) > 0 && rule.MatchFallback(buildFallbackMetadata(addrs))
			}(); fallback {
				r.dnsLogger.DebugContext(ctx, "match fallback, continue")
				continue
			}
			return response, isFakeIP, err
		}
	}
	response, err := r.getRequestMulitServer(ctx, r.defaultTransports, message)
	return response, false, err
}

func (r *Router) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	if len(message.Question) > 0 {
		r.dnsLogger.DebugContext(ctx, "exchange ", formatQuestion(message.Question[0].String()))
	}
	var (
		response *mDNS.Msg
		cached   bool
		isFakeIP bool
		err      error
	)
	defer func() {
		if r.dnsReverseMapping != nil && !isFakeIP && len(message.Question) > 0 && response != nil && len(response.Answer) > 0 {
			for _, answer := range response.Answer {
				switch record := answer.(type) {
				case *mDNS.A:
					r.dnsReverseMapping.Save(M.AddrFromIP(record.A), fqdnToDomain(record.Hdr.Name), int(record.Hdr.Ttl))
				case *mDNS.AAAA:
					r.dnsReverseMapping.Save(M.AddrFromIP(record.AAAA), fqdnToDomain(record.Hdr.Name), int(record.Hdr.Ttl))
				}
			}
		}
	}()
	if response, cached = r.dnsClient.ExchangeCache(ctx, message); cached {
		if len(message.Question) > 0 && response != nil {
			LogDNSAnswers(r.dnsLogger, ctx, message.Question[0].Name, response.Answer)
		}
		return response, nil
	}
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
	response, isFakeIP, err = r.matchDNS1(ctx, message)
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
