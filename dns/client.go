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
	ipv4Index atomic.Int32
	ipv6Index atomic.Int32
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
		newIndex := (dm.ipv4Index.Add(1) % int32(len(ipv4Answers)))
		dm.ipv4Index.Store(newIndex)
		rotatedIPv4 := reverseRotateSlice(ipv4Answers, newIndex)
		msg.Answer = removeAnswersOfType(msg.Answer, dns.TypeA)
		for _, ipv4 := range rotatedIPv4 {
			msg.Answer = append(msg.Answer, ipv4)
		}
	}
	if len(ipv6Answers) > 1 {
		newIndex := (dm.ipv6Index.Add(1) % int32(len(ipv6Answers)))
		dm.ipv6Index.Store(newIndex)
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
	cache             *freelru.Cache[dnsCacheKey, *dnsMsg]
	roundRobinIndex   *freelru.Cache[dnsCacheKey, *dnsMsg]
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
	cacheCapacity := max(options.CacheCapacity, 1024)
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
	if client.maxCacheTTL > 0 && client.minCacheTTL > client.maxCacheTTL {
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
	clientSubnet netip.Prefix
}

func (k dnsCacheKey) persistentName() string {
	if !k.clientSubnet.IsValid() {
		return k.transportTag
	}
	return k.transportTag + "\x00" + k.clientSubnet.String()
}

func (c *Client) effectiveClientSubnet(message *dns.Msg, options adapter.DNSQueryOptions) netip.Prefix {
	if options.ClientSubnet.IsValid() {
		return options.ClientSubnet
	}
	if c.clientSubnet.IsValid() {
		return c.clientSubnet
	}
	return clientSubnetFromMessage(message)
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
		c.roundRobinIndex = common.Must1(freelru.New[dnsCacheKey, *dnsMsg](c.cacheCapacity, maphash.NewHasher[dnsCacheKey]().Hash32, true))
	}
}

func (c *Client) initializeMemoryCache() {
	if c.disableCache || c.cache != nil {
		return
	}
	c.cache = common.Must1(freelru.New[dnsCacheKey, *dnsMsg](c.cacheCapacity, maphash.NewHasher[dnsCacheKey]().Hash32, true))
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

type exchangeStatus int

const (
	exchangeReady exchangeStatus = iota
	exchangeDone
	exchangeWait
)

type exchangeOperation struct {
	ctx             context.Context
	message         *dns.Msg
	question        dns.Question
	messageId       uint16
	options         adapter.DNSQueryOptions
	responseChecker func(response *dns.Msg) bool
	disableCache    bool
	cacheKey        dnsCacheKey
	releaseCond     func()
}

func (o *exchangeOperation) release() {
	if o.releaseCond != nil {
		o.releaseCond()
		o.releaseCond = nil
	}
}

func (c *Client) beginExchange(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool, allowWait bool) (*exchangeOperation, *dns.Msg, exchangeStatus, error) {
	if len(message.Question) == 0 {
		if c.logger != nil {
			c.logger.WarnContext(ctx, "bad question size: ", len(message.Question))
		}
		return nil, FixedResponseStatus(message, dns.RcodeFormatError), exchangeDone, nil
	}
	question := message.Question[0]
	if question.Qtype == dns.TypeA && options.Strategy == C.DomainStrategyIPv6Only || question.Qtype == dns.TypeAAAA && options.Strategy == C.DomainStrategyIPv4Only {
		if c.logger != nil {
			c.logger.DebugContext(ctx, "strategy rejected")
		}
		return nil, FixedResponseStatus(message, dns.RcodeSuccess), exchangeDone, nil
	}
	isSimpleRequest := len(message.Question) == 1 &&
		len(message.Ns) == 0 &&
		(len(message.Extra) == 0 || len(message.Extra) == 1 &&
			message.Extra[0].Header().Rrtype == dns.TypeOPT &&
			message.Extra[0].Header().Class > 0 &&
			message.Extra[0].Header().Ttl == 0 &&
			common.All(message.Extra[0].(*dns.OPT).Option, func(it dns.EDNS0) bool {
				return it.Option() == dns.EDNS0SUBNET
			}))
	message = c.prepareExchangeMessage(message, options)
	disableCache := !isSimpleRequest || c.disableCache || options.DisableCache
	operation := &exchangeOperation{
		message:         message,
		question:        question,
		messageId:       message.Id,
		options:         options,
		responseChecker: responseChecker,
		disableCache:    disableCache,
	}
	if !disableCache {
		cacheKey := dnsCacheKey{Question: question, transportTag: transport.Tag(), clientSubnet: c.effectiveClientSubnet(message, options)}
		operation.cacheKey = cacheKey
		cond, loaded := c.cacheLock.LoadOrStore(cacheKey, make(chan struct{}))
		if loaded {
			if !allowWait {
				return nil, nil, exchangeWait, nil
			}
			select {
			case <-cond:
			case <-ctx.Done():
				return nil, nil, exchangeDone, ctx.Err()
			}
		} else {
			operation.releaseCond = func() {
				c.cacheLock.Delete(cacheKey)
				close(cond)
			}
		}
		response, ttl, isStale := c.loadResponse(cacheKey)
		if response != nil {
			if isStale && !options.DisableOptimisticCache {
				c.backgroundRefreshDNS(transport, cacheKey, message.Copy(), options, responseChecker)
				logOptimisticResponse(c.logger, ctx, response)
				response.Id = message.Id
				operation.release()
				return nil, response, exchangeDone, nil
			} else if !isStale {
				logCachedResponse(c.logger, ctx, response, ttl)
				response.Id = message.Id
				operation.release()
				return nil, response, exchangeDone, nil
			}
		}
	}

	contextTransport, transportTagLoaded := transportTagFromContext(ctx)
	if transportTagLoaded && transport.Tag() == contextTransport {
		operation.release()
		return nil, nil, exchangeDone, E.New("DNS query loopback in transport[", contextTransport, "]")
	}
	operation.ctx = contextWithTransportTag(ctx, transport.Tag())
	if !disableCache && responseChecker != nil && c.rdrc != nil {
		rejected := c.rdrc.LoadRDRC(transport.Tag(), question.Name, question.Qtype)
		if rejected {
			operation.release()
			return nil, nil, exchangeDone, ErrResponseRejectedCached
		}
	}
	return operation, nil, exchangeReady, nil
}

func (c *Client) finishExchange(transport adapter.DNSTransport, operation *exchangeOperation, response *dns.Msg) (*dns.Msg, error) {
	ctx := operation.ctx
	question := operation.question
	disableCache := operation.disableCache || (response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError)
	if operation.responseChecker != nil {
		var rejected bool
		if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
			rejected = true
		} else {
			rejected = !operation.responseChecker(response)
		}
		if rejected {
			if !disableCache && c.rdrc != nil {
				c.rdrc.SaveRDRCAsync(transport.Tag(), question.Name, question.Qtype, c.logger)
			}
			logRejectedResponse(c.logger, ctx, response)
			return response, ErrResponseRejected
		}
	}
	timeToLive := c.applyResponseOptions(question, response, operation.options)
	if !disableCache {
		c.storeCache(operation.cacheKey, response, timeToLive)
	}
	response.Id = operation.messageId
	requestEDNSOpt := operation.message.IsEdns0()
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

func (c *Client) Exchange(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool) (*dns.Msg, error) {
	operation, earlyResponse, status, err := c.beginExchange(ctx, transport, message, options, responseChecker, true)
	if status != exchangeReady {
		return earlyResponse, err
	}
	defer operation.release()
	response, err := c.exchangeToTransport(operation.ctx, transport, operation.message, options.Timeout)
	if err != nil {
		return nil, err
	}
	return c.finishExchange(transport, operation, response)
}

func (c *Client) ExchangeAsync(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool, callback func(response *dns.Msg, err error)) {
	operation, earlyResponse, status, err := c.beginExchange(ctx, transport, message, options, responseChecker, false)
	switch status {
	case exchangeDone:
		callback(earlyResponse, err)
		return
	case exchangeWait:
		go func() {
			callback(c.Exchange(ctx, transport, message, options, responseChecker))
		}()
		return
	}
	finish := func(response *dns.Msg, exchangeErr error) {
		if exchangeErr != nil {
			operation.release()
			callback(nil, exchangeErr)
			return
		}
		finishedResponse, finishErr := c.finishExchange(transport, operation, response)
		operation.release()
		callback(finishedResponse, finishErr)
	}
	c.exchangeToTransportAsync(operation.ctx, transport, operation.message, options.Timeout, finish)
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
	switch strategy {
	case C.DomainStrategyIPv4Only:
		return c.lookupToExchange(ctx, transport, dnsName, dns.TypeA, lookupOptions, responseChecker)
	case C.DomainStrategyIPv6Only:
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

func (c *Client) storeCache(key dnsCacheKey, message *dns.Msg, timeToLive uint32) {
	if timeToLive == 0 {
		return
	}
	if c.dnsCache != nil {
		packed, err := message.Pack()
		if err == nil {
			expireAt := time.Now().Add(time.Second * time.Duration(timeToLive))
			c.dnsCache.SaveDNSCacheAsync(key.persistentName(), key.Name, key.Qtype, packed, expireAt, c.logger)
		}
		return
	}
	if c.cache == nil {
		return
	}
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
	cacheKey := dnsCacheKey{Question: question, transportTag: transport.Tag(), clientSubnet: c.effectiveClientSubnet(message, options)}
	response, _, isStale := c.loadResponse(cacheKey)
	if response == nil {
		return nil, ErrNotCached
	}
	if isStale {
		if options.DisableOptimisticCache {
			return nil, ErrNotCached
		}
		c.backgroundRefreshDNS(transport, cacheKey, c.prepareExchangeMessage(message.Copy(), options), options, responseChecker)
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

func (c *Client) loadResponse(key dnsCacheKey) (*dns.Msg, int, bool) {
	if c.dnsCache != nil {
		response, ttl, isStale := c.loadPersistentResponse(key)
		if response != nil && c.roundRobinIndex != nil {
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
	nowTTL := max(int(expireAt.Sub(timeNow).Seconds()), 0)
	response := c.getRoundRobin(cached)
	normalizeTTL(response, uint32(nowTTL))
	return response, nowTTL, false
}

func (c *Client) loadPersistentResponse(key dnsCacheKey) (*dns.Msg, int, bool) {
	rawMessage, expireAt, loaded := c.dnsCache.LoadDNSCache(key.persistentName(), key.Name, key.Qtype)
	if !loaded {
		return nil, 0, false
	}
	response := new(dns.Msg)
	err := response.Unpack(rawMessage)
	if err != nil {
		if c.logger != nil {
			c.logger.Warn("load persistent DNS cache for ", key.Name, ": unpack failed: ", err)
		}
		c.dnsCache.DeleteDNSCache(key.persistentName(), key.Name, key.Qtype, rawMessage)
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
	nowTTL := max(int(expireAt.Sub(timeNow).Seconds()), 0)
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
	timeToLive := max(computeTimeToLive(response), c.minCacheTTL)
	if c.maxCacheTTL > 0 {
		timeToLive = min(timeToLive, c.maxCacheTTL)
	}
	if options.RewriteTTL != nil {
		timeToLive = *options.RewriteTTL
	}
	normalizeTTL(response, timeToLive)
	return timeToLive
}

func (c *Client) backgroundRefreshDNS(transport adapter.DNSTransport, key dnsCacheKey, message *dns.Msg, options adapter.DNSQueryOptions, responseChecker func(response *dns.Msg) bool) {
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
				c.logger.DebugContext(ctx, "optimistic refresh failed for ", FqdnToDomain(key.Name), ": ", err)
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
					c.logger.DebugContext(ctx, "optimistic refresh rejected for ", FqdnToDomain(key.Name))
				}
				if c.rdrc != nil {
					c.rdrc.SaveRDRCAsync(transport.Tag(), key.Name, key.Qtype, c.logger)
				}
				return
			}
		} else if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
			return
		}
		timeToLive := c.applyResponseOptions(key.Question, response, options)
		c.storeCache(key, response, timeToLive)
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

func (c *Client) exchangeToTransportAsync(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, timeout time.Duration, callback func(response *dns.Msg, err error)) {
	if timeout == 0 {
		timeout = c.timeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	transport.ExchangeAsync(ctx, message, func(response *dns.Msg, err error) {
		cancel()
		if err == nil {
			stripDNSPadding(response)
			callback(response, nil)
			return
		}
		var rcodeError RcodeError
		if errors.As(err, &rcodeError) {
			callback(FixedResponseStatus(message, int(rcodeError)), nil)
			return
		}
		callback(nil, err)
	})
}

func MessageToAddresses(response *dns.Msg) []netip.Addr {
	return adapter.DNSResponseAddresses(response)
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
	source = dns.CanonicalName(source)
	target = dns.CanonicalName(target)
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
