package route

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"time"

	"github.com/sagernet/sing-box/adapter"
	dns "github.com/sagernet/sing-dns"
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

func (r *Router) matchDNS(ctx context.Context, allowFakeIP bool, index int, isAddressQuery bool) (context.Context, dns.Transport, dns.DomainStrategy, adapter.DNSRule, int) {
	metadata := adapter.ContextFrom(ctx)
	if metadata == nil {
		panic("no context")
	}
	if index < len(r.dnsRules) {
		dnsRules := r.dnsRules
		if index != -1 {
			dnsRules = dnsRules[index+1:]
		}
		for currentRuleIndex, rule := range dnsRules {
			if rule.WithAddressLimit() && !isAddressQuery {
				continue
			}
			metadata.ResetRuleCache()
			if rule.Match(metadata) {
				detour := rule.Outbound()
				transport, loaded := r.transportMap[detour]
				if !loaded {
					r.dnsLogger.ErrorContext(ctx, "transport not found: ", detour)
					continue
				}
				_, isFakeIP := transport.(adapter.FakeIPTransport)
				if isFakeIP && !allowFakeIP {
					continue
				}
				ruleIndex := currentRuleIndex
				if index != -1 {
					ruleIndex += index + 1
				}
				r.dnsLogger.DebugContext(ctx, "match[", ruleIndex, "] ", rule.String(), " => ", detour)
				if isFakeIP || rule.DisableCache() {
					ctx = dns.ContextWithDisableCache(ctx, true)
				}
				if rewriteTTL := rule.RewriteTTL(); rewriteTTL != nil {
					ctx = dns.ContextWithRewriteTTL(ctx, *rewriteTTL)
				}
				if clientSubnet := rule.ClientSubnet(); clientSubnet != nil {
					ctx = dns.ContextWithClientSubnet(ctx, *clientSubnet)
				}
				if domainStrategy, dsLoaded := r.transportDomainStrategy[transport]; dsLoaded {
					return ctx, transport, domainStrategy, rule, ruleIndex
				} else {
					return ctx, transport, r.defaultDomainStrategy, rule, ruleIndex
				}
			}
		}
	}
	if domainStrategy, dsLoaded := r.transportDomainStrategy[r.defaultTransport]; dsLoaded {
		return ctx, r.defaultTransport, domainStrategy, nil, -1
	} else {
		return ctx, r.defaultTransport, r.defaultDomainStrategy, nil, -1
	}
}

func (r *Router) matchHosts(ctx context.Context, metadata *adapter.InboundContext) (int, bool) {
	if len(r.hostsRules) == 0 {
		return 0, false
	}
	for i, rule := range r.hostsRules {
		metadata.ResetRuleCache()
		if rule.Match(metadata) {
			r.dnsLogger.DebugContext(ctx, "match[", i, "] ", rule.String())
			return i, true
		}
	}
	return 0, false
}

func (r *Router) ExchangeHosts(ctx context.Context, message *mDNS.Msg, metadata *adapter.InboundContext) (*mDNS.Msg, bool) {
	var ip4, ip6 []netip.Addr
	if i, ok := r.matchHosts(ctx, metadata); ok {
		for _, ip := range r.hostsRules[i].IP() {
			if ip.Is4In6() {
				ip = netip.AddrFrom4(ip.As4())
			}
			if ip.Is4() {
				ip4 = append(ip4, ip)
			} else {
				ip6 = append(ip6, ip)
			}
		}
		if len(message.Question) == 1 && (message.Question[0].Qtype == mDNS.TypeA || message.Question[0].Qtype == mDNS.TypeAAAA) && (len(ip4) > 0 || len(ip6) > 0) {
			response := &mDNS.Msg{
				MsgHdr: mDNS.MsgHdr{
					Id:       message.Id,
					Rcode:    mDNS.RcodeSuccess,
					Response: true,
				},
				Question: message.Question,
			}
			ttl := uint32(dns.DefaultTTL)
			if rewriteTTL, loaded := dns.RewriteTTLFromContext(ctx); loaded {
				ttl = rewriteTTL
			}
			if message.Question[0].Qtype == mDNS.TypeA && len(ip4) > 0 && r.defaultDomainStrategy != dns.DomainStrategyUseIPv6 {
				for _, ip := range ip4 {
					response.Answer = append(response.Answer, &mDNS.A{
						Hdr: mDNS.RR_Header{
							Name:   message.Question[0].Name,
							Rrtype: mDNS.TypeA,
							Class:  mDNS.ClassINET,
							Ttl:    ttl,
						},
						A: ip.AsSlice(),
					})
				}
				metadata.QueryType = message.Question[0].Qtype
				metadata.IPVersion = 4
				metadata.Domain = fqdnToDomain(message.Question[0].Name)
				return response, true
			}
			if message.Question[0].Qtype == mDNS.TypeAAAA && len(ip6) > 0 && r.defaultDomainStrategy != dns.DomainStrategyUseIPv4 {
				for _, ip := range ip6 {
					response.Answer = append(response.Answer, &mDNS.AAAA{
						Hdr: mDNS.RR_Header{
							Name:   message.Question[0].Name,
							Rrtype: mDNS.TypeAAAA,
							Class:  mDNS.ClassINET,
							Ttl:    ttl,
						},
						AAAA: ip.AsSlice(),
					})
				}
				metadata.QueryType = message.Question[0].Qtype
				metadata.IPVersion = 6
				metadata.Domain = fqdnToDomain(message.Question[0].Name)
				return response, true
			}
		}
	}
	return nil, false
}

func (r *Router) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Domain = fqdnToDomain(message.Question[0].Name)
	if len(message.Question) > 0 {
		r.dnsLogger.DebugContext(ctx, "exchange ", formatQuestion(message.Question[0].String()))
	}

	if response, ok := r.ExchangeHosts(ctx, message, metadata); ok {
		for _, recordList := range [][]mDNS.RR{response.Answer, response.Ns, response.Extra} {
			for _, record := range recordList {
				r.dnsLogger.InfoContext(ctx, "exchanged hosts ", fqdnToDomain(message.Question[0].Name), " ", mDNS.Type(record.Header().Rrtype).String(), " ", formatQuestion(record.String()))
			}
		}
		return response, nil
	}

	var (
		response  *mDNS.Msg
		cached    bool
		transport dns.Transport
		err       error
	)
	response, cached = r.dnsClient.ExchangeCache(ctx, message)
	if !cached {
		var metadata *adapter.InboundContext
		ctx, metadata = adapter.ExtendContext(ctx)
		metadata.Destination = M.Socksaddr{}
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
		var (
			strategy  dns.DomainStrategy
			rule      adapter.DNSRule
			ruleIndex int
		)
		ruleIndex = -1
		for {
			var (
				dnsCtx       context.Context
				addressLimit bool
			)
			dnsCtx, transport, strategy, rule, ruleIndex = r.matchDNS(ctx, true, ruleIndex, isAddressQuery(message))
			dnsCtx = adapter.OverrideContext(dnsCtx)
			if rule != nil && rule.WithAddressLimit() {
				addressLimit = true
				response, err = r.dnsClient.ExchangeWithResponseCheck(dnsCtx, transport, message, strategy, func(response *mDNS.Msg) bool {
					addresses, addrErr := dns.MessageToAddresses(response)
					if addrErr != nil {
						return false
					}
					metadata.DestinationAddresses = addresses
					return rule.MatchAddressLimit(metadata)
				})
			} else {
				addressLimit = false
				response, err = r.dnsClient.Exchange(dnsCtx, transport, message, strategy)
			}
			var rejected bool
			if err != nil {
				if errors.Is(err, dns.ErrResponseRejectedCached) {
					rejected = true
					r.dnsLogger.DebugContext(ctx, E.Cause(err, "response rejected for ", formatQuestion(message.Question[0].String())), " (cached)")
				} else if errors.Is(err, dns.ErrResponseRejected) {
					rejected = true
					r.dnsLogger.DebugContext(ctx, E.Cause(err, "response rejected for ", formatQuestion(message.Question[0].String())))
				} else if len(message.Question) > 0 {
					r.dnsLogger.ErrorContext(ctx, E.Cause(err, "exchange failed for ", formatQuestion(message.Question[0].String())))
				} else {
					r.dnsLogger.ErrorContext(ctx, E.Cause(err, "exchange failed for <empty query>"))
				}
			}
			if addressLimit && rejected {
				continue
			}
			break
		}
	}
	if err != nil {
		return nil, err
	}
	if r.dnsReverseMapping != nil && len(message.Question) > 0 && response != nil && len(response.Answer) > 0 {
		if _, isFakeIP := transport.(adapter.FakeIPTransport); !isFakeIP {
			for _, answer := range response.Answer {
				switch record := answer.(type) {
				case *mDNS.A:
					r.dnsReverseMapping.Save(M.AddrFromIP(record.A), fqdnToDomain(record.Hdr.Name), int(record.Hdr.Ttl))
				case *mDNS.AAAA:
					r.dnsReverseMapping.Save(M.AddrFromIP(record.AAAA), fqdnToDomain(record.Hdr.Name), int(record.Hdr.Ttl))
				}
			}
		}
	}
	return response, nil
}

func (r *Router) LookupHosts(ctx context.Context, domain string, strategy dns.DomainStrategy, metadata *adapter.InboundContext) ([]netip.Addr, bool) {
	var ip4, ip6 []netip.Addr
	if i, ok := r.matchHosts(ctx, metadata); ok {
		for _, ip := range r.hostsRules[i].IP() {
			if ip.Is4In6() {
				ip = netip.AddrFrom4(ip.As4())
			}
			if ip.Is4() {
				ip4 = append(ip4, ip)
			} else {
				ip6 = append(ip6, ip)
			}
		}
		switch strategy {
		case dns.DomainStrategyUseIPv4:
			if len(ip4) > 0 {
				return ip4, true
			}
		case dns.DomainStrategyUseIPv6:
			if len(ip6) > 0 {
				return ip6, true
			}
		case dns.DomainStrategyPreferIPv4, dns.DomainStrategyAsIS:
			if len(ip4) > 0 || len(ip6) > 0 {
				return append(ip4, ip6...), true
			}
		case dns.DomainStrategyPreferIPv6:
			if len(ip4) > 0 || len(ip6) > 0 {
				return append(ip6, ip4...), true
			}
		}
	}
	return []netip.Addr{}, false
}

func (r *Router) Lookup(ctx context.Context, domain string, strategy dns.DomainStrategy) ([]netip.Addr, error) {
	var (
		responseAddrs []netip.Addr
		cached        bool
		err           error
	)
	responseAddrs, cached = r.dnsClient.LookupCache(ctx, domain, strategy)
	if cached {
		if len(responseAddrs) == 0 {
			return nil, dns.RCodeNameError
		}
		return responseAddrs, nil
	}
	r.dnsLogger.DebugContext(ctx, "lookup domain ", domain)
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Destination = M.Socksaddr{}
	domain = fqdnToDomain(domain)
	metadata.Domain = domain

	if ips, ok := r.LookupHosts(ctx, domain, strategy, metadata); ok {
		r.dnsLogger.InfoContext(ctx, "lookup hosts succeed for ", domain, ": ", strings.Join(F.MapToString(ips), " "))
		return ips, nil
	}

	var (
		transport         dns.Transport
		transportStrategy dns.DomainStrategy
		rule              adapter.DNSRule
		ruleIndex         int
	)
	ruleIndex = -1
	for {
		var (
			dnsCtx       context.Context
			addressLimit bool
		)
		dnsCtx, transport, transportStrategy, rule, ruleIndex = r.matchDNS(ctx, false, ruleIndex, true)
		dnsCtx = adapter.OverrideContext(dnsCtx)
		if strategy == dns.DomainStrategyAsIS {
			strategy = transportStrategy
		}
		if rule != nil && rule.WithAddressLimit() {
			addressLimit = true
			responseAddrs, err = r.dnsClient.LookupWithResponseCheck(dnsCtx, transport, domain, strategy, func(responseAddrs []netip.Addr) bool {
				metadata.DestinationAddresses = responseAddrs
				return rule.MatchAddressLimit(metadata)
			})
		} else {
			addressLimit = false
			responseAddrs, err = r.dnsClient.Lookup(dnsCtx, transport, domain, strategy)
		}
		if err != nil {
			if errors.Is(err, dns.ErrResponseRejectedCached) {
				r.dnsLogger.DebugContext(ctx, "response rejected for ", domain, " (cached)")
			} else if errors.Is(err, dns.ErrResponseRejected) {
				r.dnsLogger.DebugContext(ctx, "response rejected for ", domain)
			} else {
				r.dnsLogger.ErrorContext(ctx, E.Cause(err, "lookup failed for ", domain))
			}
		} else if len(responseAddrs) == 0 {
			r.dnsLogger.ErrorContext(ctx, "lookup failed for ", domain, ": empty result")
			err = dns.RCodeNameError
		}
		if !addressLimit || err == nil {
			break
		}
	}
	if len(responseAddrs) > 0 {
		r.dnsLogger.InfoContext(ctx, "lookup succeed for ", domain, ": ", strings.Join(F.MapToString(responseAddrs), " "))
	}
	return responseAddrs, err
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

func isAddressQuery(message *mDNS.Msg) bool {
	for _, question := range message.Question {
		if question.Qtype == mDNS.TypeA || question.Qtype == mDNS.TypeAAAA || question.Qtype == mDNS.TypeHTTPS {
			return true
		}
	}
	return false
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
