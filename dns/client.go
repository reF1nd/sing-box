package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/compatible"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	"github.com/sagernet/sing/common/task"
	"github.com/sagernet/sing/contrab/freelru"
	"github.com/sagernet/sing/contrab/maphash"

	"github.com/miekg/dns"
)

var (
	ErrNoRawSupport           = E.New("no raw query support by current transport")
	ErrNotCached              = E.New("not cached")
	ErrResponseRejected       = E.New("response rejected")
	ErrResponseRejectedCached = E.Extend(ErrResponseRejected, "cached")
)

var _ adapter.DNSClient = (*Client)(nil)

func reverseRotateSlice[T any](slice []T, steps int32) []T {
	if len(slice) <= 1 {
		return slice
	}
	steps = steps % int32(len(slice))
	return append(slice[len(slice)-int(steps):], slice[:len(slice)-int(steps)]...)
}

func removeAnswersOfType(answers []dns.RR, rrType uint16) []dns.RR {
	var filteredAnswers []dns.RR
	for _, ans := range answers {
		if ans.Header().Rrtype != rrType {
			filteredAnswers = append(filteredAnswers, ans)
		}
	}
	return filteredAnswers
}

type dnsMsg struct {
	ipv4Index int32
	ipv6Index int32
	msg       *dns.Msg
}

func (dm *dnsMsg) applyRoundRobin(msg *dns.Msg) {
	var (
		ipv4Answers []*dns.A
		ipv6Answers []*dns.AAAA
	)
	for _, ans := range msg.Answer {
		switch a := ans.(type) {
		case *dns.A:
			ipv4Answers = append(ipv4Answers, a)
		case *dns.AAAA:
			ipv6Answers = append(ipv6Answers, a)
		}
	}
	if len(ipv4Answers) > 1 {
		newIndex := (atomic.AddInt32(&dm.ipv4Index, 1) % int32(len(ipv4Answers)))
		atomic.StoreInt32(&dm.ipv4Index, newIndex)
		rotatedIPv4 := reverseRotateSlice(ipv4Answers, newIndex)
		msg.Answer = removeAnswersOfType(msg.Answer, dns.TypeA)
		for _, ipv4 := range rotatedIPv4 {
			msg.Answer = append(msg.Answer, ipv4)
		}
	}
	if len(ipv6Answers) > 1 {
		newIndex := (atomic.AddInt32(&dm.ipv6Index, 1) % int32(len(ipv6Answers)))
		atomic.StoreInt32(&dm.ipv6Index, newIndex)
		rotatedIPv6 := reverseRotateSlice(ipv6Answers, newIndex)
		msg.Answer = removeAnswersOfType(msg.Answer, dns.TypeAAAA)
		for _, ipv6 := range rotatedIPv6 {
			msg.Answer = append(msg.Answer, ipv6)
		}
	}
}

func (dm *dnsMsg) RoundRobin() *dns.Msg {
	rotatedMsg := dm.msg.Copy()
	dm.applyRoundRobin(rotatedMsg)
	return rotatedMsg
}

type Client struct {
	ctx               context.Context
	timeout           time.Duration
	disableCache      bool
	disableExpire     bool
	optimisticTimeout time.Duration
	cacheCapacity     uint32
	roundRobinCache   bool
	minCacheTTL       uint32
	maxCacheTTL       uint32
	clientSubnet      netip.Prefix
	rdrc              adapter.RDRCStore
	initRDRCFunc      func() adapter.RDRCStore
	dnsCache          adapter.DNSCacheStore
	initDNSCacheFunc  func() adapter.DNSCacheStore
	logger            logger.ContextLogger
	cache             freelru.Cache[dnsCacheKey, *dnsMsg]
	roundRobinIndex   freelru.Cache[dnsCacheKey, *dnsMsg]
	cacheLock         compatible.Map[dnsCacheKey, chan struct{}]
	backgroundRefresh compatible.Map[dnsCacheKey, struct{}]
}

type ClientOptions struct {
	Context           context.Context
	Timeout           time.Duration
	DisableCache      bool
	DisableExpire     bool
	OptimisticTimeout time.Duration
	RoundRobinCache   bool
	CacheCapacity     uint32
	MinCacheTTL       uint32
	MaxCacheTTL       uint32
	ClientSubnet      netip.Prefix
	RDRC              func() adapter.RDRCStore
	DNSCache          func() adapter.DNSCacheStore
	Logger            logger.ContextLogger
}

func NewClient(options ClientOptions) *Client {
	cacheCapacity := options.CacheCapacity
	if cacheCapacity < 1024 {
		cacheCapacity = 1024
	}
	client := &Client{
		ctx:               options.Context,
		timeout:           options.Timeout,
		disableCache:      options.DisableCache,
		disableExpire:     options.DisableExpire,
		optimisticTimeout: options.OptimisticTimeout,
		cacheCapacity:     cacheCapacity,
		roundRobinCache:   options.RoundRobinCache,
		minCacheTTL:       options.MinCacheTTL,
		maxCacheTTL:       options.MaxCacheTTL,
		clientSubnet:      options.ClientSubnet,
		initRDRCFunc:      options.RDRC,
		initDNSCacheFunc:  options.DNSCache,
		logger:            options.Logger,
	}
	if client.maxCacheTTL == 0 {
		client.maxCacheTTL = 86400
	}
	if client.minCacheTTL > client.maxCacheTTL {
		client.maxCacheTTL = client.minCacheTTL
	}
	if client.timeout == 0 {
		client.timeout = C.DNSTimeout
	}
	if !client.disableCache && client.initDNSCacheFunc == nil {
		client.initializeMemoryCache()
	}
	return client
}

type dnsCacheKey struct {
	dns.Question
	transportTag string
}

func (c *Client) Start() {
	if c.initRDRCFunc != nil {
		c.rdrc = c.initRDRCFunc()
	}
	if c.initDNSCacheFunc != nil {
		c.dnsCache = c.initDNSCacheFunc()
	}
	if c.dnsCache == nil {
		c.initializeMemoryCache()
	} else if c.roundRobinCache {
		c.roundRobinIndex = common.Must1(freelru.NewSharded[dnsCacheKey, *dnsMsg](c.cacheCapacity, maphash.NewHasher[dnsCacheKey]().Hash32))
	}
}

func (c *Client) initializeMemoryCache() {
	if c.disableCache || c.cache != nil {
		return
	}
	c.cache = common.Must1(freelru.NewSharded[dnsCacheKey, *dnsMsg](c.cacheCapacity, maphash.NewHasher[dnsCacheKey]().Hash32))
}

func extractNegativeTTL(response *dns.Msg) (uint32, bool) {
	for _, record := range response.Ns {
		if soa, isSOA := record.(*dns.SOA); isSOA {
			soaTTL := soa.Header().Ttl
			soaMinimum := soa.Minttl
			if soaTTL < soaMinimum {
				return soaTTL, true
			}
			return soaMinimum, true
		}
	}
	return 0, false
}

func computeTimeToLive(response *dns.Msg) uint32 {
	var timeToLive uint32
	if len(response.Answer) == 0 {
		if soaTTL, hasSOA := extractNegativeTTL(response); hasSOA {
			return soaTTL
		}
	}
	for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range recordList {
			if record.Header().Rrtype == dns.TypeOPT {
				continue
			}
			if timeToLive == 0 || record.Header().Ttl > 0 && record.Header().Ttl < timeToLive {
				timeToLive = record.Header().Ttl
			}
		}
	}
	return timeToLive
}

func normalizeTTL(response *dns.Msg, timeToLive uint32) {
	for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range recordList {
			if record.Header().Rrtype == dns.TypeOPT {
				continue
			}
			record.Header().Ttl = timeToLive
		}
	}
}

func (c *Client) Exchange(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool) (*dns.Msg, error) {
	if len(message.Question) == 0 {
		if c.logger != nil {
			c.logger.WarnContext(ctx, "bad question size: ", len(message.Question))
		}
		return FixedResponseStatus(message, dns.RcodeFormatError), nil
	}
	question := message.Question[0]
	if question.Qtype == dns.TypeA && options.Strategy == C.DomainStrategyIPv6Only || question.Qtype == dns.TypeAAAA && options.Strategy == C.DomainStrategyIPv4Only {
		if c.logger != nil {
			c.logger.DebugContext(ctx, "strategy rejected")
		}
		return FixedResponseStatus(message, dns.RcodeSuccess), nil
	}
	message = c.prepareExchangeMessage(message, options)

	isSimpleRequest := len(message.Question) == 1 &&
		len(message.Ns) == 0 &&
		(len(message.Extra) == 0 || len(message.Extra) == 1 &&
			message.Extra[0].Header().Rrtype == dns.TypeOPT &&
			message.Extra[0].Header().Class > 0 &&
			message.Extra[0].Header().Ttl == 0 &&
			len(message.Extra[0].(*dns.OPT).Option) == 0) &&
		!options.ClientSubnet.IsValid()
	disableCache := !isSimpleRequest || c.disableCache || options.DisableCache
	if !disableCache {
		cacheKey := dnsCacheKey{Question: question, transportTag: transport.Tag()}
		cond, loaded := c.cacheLock.LoadOrStore(cacheKey, make(chan struct{}))
		if loaded {
			select {
			case <-cond:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		} else {
			defer func() {
				c.cacheLock.Delete(cacheKey)
				close(cond)
			}()
		}
		response, ttl, isStale := c.loadResponse(question, transport)
		if response != nil {
			if isStale && !options.DisableOptimisticCache {
				c.backgroundRefreshDNS(transport, question, message.Copy(), options, responseChecker)
				logOptimisticResponse(c.logger, ctx, response)
				response.Id = message.Id
				return response, nil
			} else if !isStale {
				logCachedResponse(c.logger, ctx, response, ttl)
				response.Id = message.Id
				return response, nil
			}
		}
	}

	messageId := message.Id
	contextTransport, clientSubnetLoaded := transportTagFromContext(ctx)
	if clientSubnetLoaded && transport.Tag() == contextTransport {
		return nil, E.New("DNS query loopback in transport[", contextTransport, "]")
	}
	ctx = contextWithTransportTag(ctx, transport.Tag())
	if !disableCache && responseChecker != nil && c.rdrc != nil {
		rejected := c.rdrc.LoadRDRC(transport.Tag(), question.Name, question.Qtype)
		if rejected {
			return nil, ErrResponseRejectedCached
		}
	}
	response, err := c.exchangeToTransport(ctx, transport, message, options.Timeout)
	if err != nil {
		return nil, err
	}
	disableCache = disableCache || (response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError)
	if responseChecker != nil {
		var rejected bool
		if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
			rejected = true
		} else {
			rejected = !responseChecker(response)
		}
		if rejected {
			if !disableCache && c.rdrc != nil {
				c.rdrc.SaveRDRCAsync(transport.Tag(), question.Name, question.Qtype, c.logger)
			}
			logRejectedResponse(c.logger, ctx, response)
			return response, ErrResponseRejected
		}
	}
	timeToLive := c.applyResponseOptions(question, response, options)
	if !disableCache {
		c.storeCache(transport, question, response, timeToLive)
	}
	response.Id = messageId
	requestEDNSOpt := message.IsEdns0()
	responseEDNSOpt := response.IsEdns0()
	if responseEDNSOpt != nil && (requestEDNSOpt == nil || requestEDNSOpt.Version() < responseEDNSOpt.Version()) {
		response.Extra = common.Filter(response.Extra, func(it dns.RR) bool {
			return it.Header().Rrtype != dns.TypeOPT
		})
		if requestEDNSOpt != nil {
			response.SetEdns0(responseEDNSOpt.UDPSize(), responseEDNSOpt.Do())
		}
	}
	logExchangedResponse(c.logger, ctx, response, timeToLive)
	return response, nil
}

func (c *Client) Lookup(ctx context.Context, transport adapter.DNSTransport, domain string, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool) ([]netip.Addr, error) {
	domain = FqdnToDomain(domain)
	dnsName := dns.Fqdn(domain)
	var strategy C.DomainStrategy
	if options.LookupStrategy != C.DomainStrategyAsIS {
		strategy = options.LookupStrategy
	} else {
		strategy = options.Strategy
	}
	lookupOptions := options
	if options.LookupStrategy != C.DomainStrategyAsIS {
		lookupOptions.Strategy = strategy
	}
	if strategy == C.DomainStrategyIPv4Only {
		return c.lookupToExchange(ctx, transport, dnsName, dns.TypeA, lookupOptions, responseChecker)
	} else if strategy == C.DomainStrategyIPv6Only {
		return c.lookupToExchange(ctx, transport, dnsName, dns.TypeAAAA, lookupOptions, responseChecker)
	}
	var response4 []netip.Addr
	var response6 []netip.Addr
	var group task.Group
	group.Append("exchange4", func(ctx context.Context) error {
		response, err := c.lookupToExchange(ctx, transport, dnsName, dns.TypeA, lookupOptions, responseChecker)
		if err != nil {
			return err
		}
		response4 = response
		return nil
	})
	group.Append("exchange6", func(ctx context.Context) error {
		response, err := c.lookupToExchange(ctx, transport, dnsName, dns.TypeAAAA, lookupOptions, responseChecker)
		if err != nil {
			return err
		}
		response6 = response
		return nil
	})
	err := group.Run(ctx)
	if len(response4) == 0 && len(response6) == 0 {
		return nil, err
	}
	return sortAddresses(response4, response6, strategy), nil
}

func (c *Client) ClearCache() {
	if c.cache != nil {
		c.cache.Purge()
	}
	if c.dnsCache != nil {
		err := c.dnsCache.ClearDNSCache()
		if err != nil && c.logger != nil {
			c.logger.Warn("clear DNS cache: ", err)
		}
	}
}

func sortAddresses(response4 []netip.Addr, response6 []netip.Addr, strategy C.DomainStrategy) []netip.Addr {
	if strategy == C.DomainStrategyPreferIPv6 {
		return append(response6, response4...)
	} else {
		return append(response4, response6...)
	}
}

func (c *Client) storeCache(transport adapter.DNSTransport, question dns.Question, message *dns.Msg, timeToLive uint32) {
	if timeToLive == 0 {
		return
	}
	if c.dnsCache != nil {
		packed, err := message.Pack()
		if err == nil {
			expireAt := time.Now().Add(time.Second * time.Duration(timeToLive))
			c.dnsCache.SaveDNSCacheAsync(transport.Tag(), question.Name, question.Qtype, packed, expireAt, c.logger)
		}
		return
	}
	if c.cache == nil {
		return
	}
	key := dnsCacheKey{Question: question, transportTag: transport.Tag()}
	if c.disableExpire {
		c.cache.Add(key, &dnsMsg{msg: message.Copy()})
	} else {
		c.cache.AddWithLifetime(key, &dnsMsg{msg: message.Copy()}, time.Second*time.Duration(timeToLive))
	}
}

func (c *Client) lookupToExchange(ctx context.Context, transport adapter.DNSTransport, name string, qType uint16, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool) ([]netip.Addr, error) {
	question := dns.Question{
		Name:   name,
		Qtype:  qType,
		Qclass: dns.ClassINET,
	}
	message := dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: []dns.Question{question},
	}
	disableCache := c.disableCache || options.DisableCache
	if !disableCache {
		cachedAddresses, err := c.questionCache(ctx, transport, &message, options, responseChecker)
		if err != ErrNotCached {
			return cachedAddresses, err
		}
	}
	response, err := c.Exchange(ctx, transport, &message, options, responseChecker)
	if err != nil {
		return nil, err
	}
	if response.Rcode != dns.RcodeSuccess {
		return nil, RcodeError(response.Rcode)
	}
	return MessageToAddresses(response), nil
}

func (c *Client) questionCache(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool) ([]netip.Addr, error) {
	question := message.Question[0]
	response, _, isStale := c.loadResponse(question, transport)
	if response == nil {
		return nil, ErrNotCached
	}
	if isStale {
		if options.DisableOptimisticCache {
			return nil, ErrNotCached
		}
		c.backgroundRefreshDNS(transport, question, c.prepareExchangeMessage(message.Copy(), options), options, responseChecker)
		logOptimisticResponse(c.logger, ctx, response)
	}
	if response.Rcode != dns.RcodeSuccess {
		return nil, RcodeError(response.Rcode)
	}
	return MessageToAddresses(response), nil
}

func (c *Client) getRoundRobin(response *dnsMsg) *dns.Msg {
	if c.roundRobinCache {
		return response.RoundRobin()
	} else {
		return response.msg.Copy()
	}
}

func (c *Client) loadResponse(question dns.Question, transport adapter.DNSTransport) (*dns.Msg, int, bool) {
	if c.dnsCache != nil {
		response, ttl, isStale := c.loadPersistentResponse(question, transport)
		if response != nil && c.roundRobinIndex != nil {
			key := dnsCacheKey{Question: question, transportTag: transport.Tag()}
			state, loaded := c.roundRobinIndex.Get(key)
			if !loaded {
				state = &dnsMsg{}
				c.roundRobinIndex.Add(key, state)
			}
			state.applyRoundRobin(response)
		}
		return response, ttl, isStale
	}
	if c.cache == nil {
		return nil, 0, false
	}
	key := dnsCacheKey{Question: question, transportTag: transport.Tag()}
	if c.disableExpire {
		cached, loaded := c.cache.Get(key)
		if !loaded {
			return nil, 0, false
		}
		return c.getRoundRobin(cached), 0, false
	}
	cached, expireAt, loaded := c.cache.GetWithLifetimeNoExpire(key)
	if !loaded {
		return nil, 0, false
	}
	timeNow := time.Now()
	if timeNow.After(expireAt) {
		if c.optimisticTimeout > 0 && timeNow.Before(expireAt.Add(c.optimisticTimeout)) {
			response := c.getRoundRobin(cached)
			normalizeTTL(response, 1)
			return response, 0, true
		}
		c.cache.Remove(key)
		return nil, 0, false
	}
	nowTTL := int(expireAt.Sub(timeNow).Seconds())
	if nowTTL < 0 {
		nowTTL = 0
	}
	response := c.getRoundRobin(cached)
	normalizeTTL(response, uint32(nowTTL))
	return response, nowTTL, false
}

func (c *Client) loadPersistentResponse(question dns.Question, transport adapter.DNSTransport) (*dns.Msg, int, bool) {
	rawMessage, expireAt, loaded := c.dnsCache.LoadDNSCache(transport.Tag(), question.Name, question.Qtype)
	if !loaded {
		return nil, 0, false
	}
	response := new(dns.Msg)
	err := response.Unpack(rawMessage)
	if err != nil {
		if c.logger != nil {
			c.logger.Warn("load persistent DNS cache for ", question.Name, ": unpack failed: ", err)
		}
		c.dnsCache.DeleteDNSCache(transport.Tag(), question.Name, question.Qtype)
		return nil, 0, false
	}
	if c.disableExpire {
		return response, 0, false
	}
	timeNow := time.Now()
	if timeNow.After(expireAt) {
		if c.optimisticTimeout > 0 && timeNow.Before(expireAt.Add(c.optimisticTimeout)) {
			normalizeTTL(response, 1)
			return response, 0, true
		}
		return nil, 0, false
	}
	nowTTL := int(expireAt.Sub(timeNow).Seconds())
	if nowTTL < 0 {
		nowTTL = 0
	}
	normalizeTTL(response, uint32(nowTTL))
	return response, nowTTL, false
}

func (c *Client) applyResponseOptions(question dns.Question, response *dns.Msg, options adapter.DNSQueryOptions) uint32 {
	if question.Qtype == dns.TypeHTTPS && (options.Strategy == C.DomainStrategyIPv4Only || options.Strategy == C.DomainStrategyIPv6Only) {
		for _, rr := range response.Answer {
			https, isHTTPS := rr.(*dns.HTTPS)
			if !isHTTPS {
				continue
			}
			content := https.SVCB
			content.Value = common.Filter(content.Value, func(it dns.SVCBKeyValue) bool {
				if options.Strategy == C.DomainStrategyIPv4Only {
					return it.Key() != dns.SVCB_IPV6HINT
				}
				return it.Key() != dns.SVCB_IPV4HINT
			})
			https.SVCB = content
		}
	}
	timeToLive := computeTimeToLive(response)
	if timeToLive < c.minCacheTTL {
		timeToLive = c.minCacheTTL
	}
	if timeToLive > c.maxCacheTTL {
		timeToLive = c.maxCacheTTL
	}
	if options.RewriteTTL != nil {
		timeToLive = *options.RewriteTTL
	}
	normalizeTTL(response, timeToLive)
	return timeToLive
}

func (c *Client) backgroundRefreshDNS(transport adapter.DNSTransport, question dns.Question, message *dns.Msg, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool) {
	key := dnsCacheKey{Question: question, transportTag: transport.Tag()}
	_, loaded := c.backgroundRefresh.LoadOrStore(key, struct{}{})
	if loaded {
		return
	}
	go func() {
		defer c.backgroundRefresh.Delete(key)
		ctx := contextWithTransportTag(c.ctx, transport.Tag())
		response, err := c.exchangeToTransport(ctx, transport, message, options.Timeout)
		if err != nil {
			if c.logger != nil {
				c.logger.DebugContext(ctx, "optimistic refresh failed for ", FqdnToDomain(question.Name), ": ", err)
			}
			return
		}
		if responseChecker != nil {
			var rejected bool
			if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
				rejected = true
			} else {
				rejected = !responseChecker(response)
			}
			if rejected {
				if c.logger != nil {
					c.logger.DebugContext(ctx, "optimistic refresh rejected for ", FqdnToDomain(question.Name))
				}
				if c.rdrc != nil {
					c.rdrc.SaveRDRCAsync(transport.Tag(), question.Name, question.Qtype, c.logger)
				}
				return
			}
		} else if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
			return
		}
		timeToLive := c.applyResponseOptions(question, response, options)
		c.storeCache(transport, question, response, timeToLive)
		logRefreshedResponse(c.logger, ctx, response, timeToLive)
	}()
}

func (c *Client) prepareExchangeMessage(message *dns.Msg, options adapter.DNSQueryOptions) *dns.Msg {
	clientSubnet := options.ClientSubnet
	if !clientSubnet.IsValid() {
		clientSubnet = c.clientSubnet
	}
	if clientSubnet.IsValid() {
		message = SetClientSubnet(message, clientSubnet)
	}
	return message
}

func stripDNSPadding(response *dns.Msg) {
	for _, record := range response.Extra {
		opt, isOpt := record.(*dns.OPT)
		if !isOpt {
			continue
		}
		opt.Option = common.Filter(opt.Option, func(it dns.EDNS0) bool {
			return it.Option() != dns.EDNS0PADDING
		})
	}
}

func (c *Client) exchangeToTransport(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, timeout time.Duration) (*dns.Msg, error) {
	if timeout == 0 {
		timeout = c.timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	response, err := transport.Exchange(ctx, message)
	if err == nil {
		stripDNSPadding(response)
		return response, nil
	}
	var rcodeError RcodeError
	if errors.As(err, &rcodeError) {
		return FixedResponseStatus(message, int(rcodeError)), nil
	}
	return nil, err
}

func MessageToAddresses(response *dns.Msg) []netip.Addr {
	return adapter.DNSResponseAddresses(response)
}

func wrapError(err error) error {
	switch dnsErr := err.(type) {
	case *net.DNSError:
		if dnsErr.IsNotFound {
			return RcodeNameError
		}
	case *net.AddrError:
		return RcodeNameError
	}
	return err
}

type transportKey struct{}

func contextWithTransportTag(ctx context.Context, transportTag string) context.Context {
	return context.WithValue(ctx, transportKey{}, transportTag)
}

func transportTagFromContext(ctx context.Context) (string, bool) {
	value, loaded := ctx.Value(transportKey{}).(string)
	return value, loaded
}

type aliasChainContextKey struct{}

func ContextWithAliasResolution(ctx context.Context, source, target string) (context.Context, bool) {
	if source == target {
		return ctx, true
	}
	var chain map[string]struct{}
	if existing, ok := ctx.Value(aliasChainContextKey{}).(map[string]struct{}); ok {
		if _, found := existing[target]; found {
			return ctx, true
		}
		chain = make(map[string]struct{}, len(existing)+2)
		for k := range existing {
			chain[k] = struct{}{}
		}
	} else {
		chain = make(map[string]struct{}, 2)
	}
	chain[source] = struct{}{}
	chain[target] = struct{}{}
	return context.WithValue(ctx, aliasChainContextKey{}, chain), false
}

func FixedResponseStatus(message *dns.Msg, rcode int) *dns.Msg {
	return &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 message.Id,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Rcode:              rcode,
		},
		Question: message.Question,
	}
}

func FixedResponse(id uint16, question dns.Question, addresses []netip.Addr, timeToLive uint32) *dns.Msg {
	response := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 id,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Rcode:              dns.RcodeSuccess,
		},
		Question: []dns.Question{question},
	}
	for _, address := range addresses {
		if address.Is4() && question.Qtype == dns.TypeA {
			response.Answer = append(response.Answer, &dns.A{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    timeToLive,
				},
				A: address.AsSlice(),
			})
		} else if address.Is6() && question.Qtype == dns.TypeAAAA {
			response.Answer = append(response.Answer, &dns.AAAA{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeAAAA,
					Class:  dns.ClassINET,
					Ttl:    timeToLive,
				},
				AAAA: address.AsSlice(),
			})
		}
	}
	return &response
}

func FixedResponseCNAME(id uint16, question dns.Question, record string, timeToLive uint32) *dns.Msg {
	response := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 id,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Rcode:              dns.RcodeSuccess,
		},
		Question: []dns.Question{question},
		Answer: []dns.RR{
			&dns.CNAME{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeCNAME,
					Class:  dns.ClassINET,
					Ttl:    timeToLive,
				},
				Target: record,
			},
		},
	}
	return &response
}

func FixedResponseTXT(id uint16, question dns.Question, records []string, timeToLive uint32) *dns.Msg {
	response := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 id,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Rcode:              dns.RcodeSuccess,
		},
		Question: []dns.Question{question},
		Answer: []dns.RR{
			&dns.TXT{
				Hdr: dns.RR_Header{
					Name:   question.Name,
					Rrtype: dns.TypeA,
					Class:  dns.ClassINET,
					Ttl:    timeToLive,
				},
				Txt: records,
			},
		},
	}
	return &response
}

func FixedResponseMX(id uint16, question dns.Question, records []*net.MX, timeToLive uint32) *dns.Msg {
	response := dns.Msg{
		MsgHdr: dns.MsgHdr{
			Id:                 id,
			Response:           true,
			Authoritative:      true,
			RecursionDesired:   true,
			RecursionAvailable: true,
			Rcode:              dns.RcodeSuccess,
		},
		Question: []dns.Question{question},
	}
	for _, record := range records {
		response.Answer = append(response.Answer, &dns.MX{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    timeToLive,
			},
			Preference: record.Pref,
			Mx:         record.Host,
		})
	}
	return &response
}
