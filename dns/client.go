package dns

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/compatible"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
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
	ipv4Index  atomic.Int32
	ipv6Index  atomic.Int32
	msg        *dns.Msg
	expireTime time.Time
	lazyCache  bool
}

func (dm *dnsMsg) RoundRobin() *dns.Msg {
	rotatedMsg := dm.msg.Copy()
	var (
		ipv4Answers []*dns.A
		ipv6Answers []*dns.AAAA
	)
	for _, ans := range rotatedMsg.Answer {
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
		rotatedMsg.Answer = removeAnswersOfType(rotatedMsg.Answer, dns.TypeA)
		for _, ipv4 := range rotatedIPv4 {
			rotatedMsg.Answer = append(rotatedMsg.Answer, ipv4)
		}
	}
	if len(ipv6Answers) > 1 {
		newIndex := (dm.ipv6Index.Add(1) % int32(len(ipv6Answers)))
		dm.ipv6Index.Store(newIndex)
		rotatedIPv6 := reverseRotateSlice(ipv6Answers, newIndex)
		rotatedMsg.Answer = removeAnswersOfType(rotatedMsg.Answer, dns.TypeAAAA)
		for _, ipv6 := range rotatedIPv6 {
			rotatedMsg.Answer = append(rotatedMsg.Answer, ipv6)
		}
	}
	return rotatedMsg
}

type Client struct {
	timeout                time.Duration
	disableCache           bool
	disableExpire          bool
	independentCache       bool
	cacheClientSubnet      bool
	roundRobinCache        bool
	useLazyCache           bool
	lazyCacheTTL           uint32
	minCacheTTL            uint32
	maxCacheTTL            uint32
	clientSubnet           netip.Prefix
	rdrc                   adapter.RDRCStore
	initRDRCFunc           func() adapter.RDRCStore
	logger                 logger.ContextLogger
	cache                  freelru.Cache[dnsCacheKey, *dnsMsg]
	cacheLock              compatible.Map[transportCacheKey, chan struct{}]
	transportCache         freelru.Cache[transportCacheKey, *dnsMsg]
	transportCacheLock     compatible.Map[transportCacheKey, chan struct{}]
	cacheUpdating          map[dnsCacheKey]struct{}
	transportCacheUpdating map[transportCacheKey]struct{}
	updateAccess           sync.Mutex
}

type ClientOptions struct {
	Timeout           time.Duration
	DisableCache      bool
	DisableExpire     bool
	IndependentCache  bool
	CacheClientSubnet bool
	RoundRobinCache   bool
	LazyCacheTTL      uint32
	CacheCapacity     uint32
	ClientSubnet      netip.Prefix
	MinCacheTTL       uint32
	MaxCacheTTL       uint32
	RDRC              func() adapter.RDRCStore
	Logger            logger.ContextLogger
}

func NewClient(options ClientOptions) *Client {
	client := &Client{
		timeout:           options.Timeout,
		disableCache:      options.DisableCache,
		disableExpire:     options.DisableExpire,
		independentCache:  options.IndependentCache,
		cacheClientSubnet: options.CacheClientSubnet,
		roundRobinCache:   options.RoundRobinCache,
		useLazyCache:      options.LazyCacheTTL > 0,
		lazyCacheTTL:      options.LazyCacheTTL,
		clientSubnet:      options.ClientSubnet,
		minCacheTTL:       options.MinCacheTTL,
		maxCacheTTL:       options.MaxCacheTTL,
		initRDRCFunc:      options.RDRC,
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
	cacheCapacity := max(options.CacheCapacity, 1024)
	if !client.disableCache {
		if !client.independentCache {
			client.cache = common.Must1(freelru.NewSharded[dnsCacheKey, *dnsMsg](cacheCapacity, maphash.NewHasher[dnsCacheKey]().Hash32))
			client.cacheUpdating = make(map[dnsCacheKey]struct{})
		} else {
			client.transportCache = common.Must1(freelru.NewSharded[transportCacheKey, *dnsMsg](cacheCapacity, maphash.NewHasher[transportCacheKey]().Hash32))
			client.transportCacheUpdating = make(map[transportCacheKey]struct{})
		}
	}
	return client
}

type dnsCacheKey struct {
	dns.Question
	clientSubnet netip.Prefix
}

type transportCacheKey struct {
	dnsCacheKey
	transportTag string
}

func (k dnsCacheKey) withTransport(transportTag string) transportCacheKey {
	return transportCacheKey{dnsCacheKey: k, transportTag: transportTag}
}

func (k dnsCacheKey) rdrcKey(transportTag string) adapter.DNSCacheKey {
	return adapter.DNSCacheKey{
		TransportName: transportTag,
		QuestionName:  k.Name,
		QType:         k.Qtype,
		ClientSubnet:  k.clientSubnet,
	}
}

func loadRDRC(store adapter.RDRCStore, key adapter.DNSCacheKey) bool {
	if !key.ClientSubnet.IsValid() {
		return store.LoadRDRC(key.TransportName, key.QuestionName, key.QType)
	}
	keyedStore, loaded := store.(adapter.RDRCStoreWithKey)
	if !loaded {
		return false
	}
	return keyedStore.LoadRDRCWithKey(key)
}

func saveRDRCAsync(store adapter.RDRCStore, key adapter.DNSCacheKey, logger logger.Logger) {
	if !key.ClientSubnet.IsValid() {
		store.SaveRDRCAsync(key.TransportName, key.QuestionName, key.QType, logger)
		return
	}
	keyedStore, loaded := store.(adapter.RDRCStoreWithKey)
	if !loaded {
		return
	}
	keyedStore.SaveRDRCAsyncWithKey(key, logger)
}

func (c *Client) Start() {
	if c.initRDRCFunc != nil {
		c.rdrc = c.initRDRCFunc()
	}
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

func (c *Client) effectiveClientSubnet(options adapter.DNSQueryOptions) netip.Prefix {
	clientSubnet := options.ClientSubnet
	if !clientSubnet.IsValid() {
		clientSubnet = c.clientSubnet
	}
	if clientSubnet.IsValid() {
		clientSubnet = clientSubnet.Masked()
	}
	return clientSubnet
}

func isSimpleDNSRequest(message *dns.Msg, clientSubnet netip.Prefix) bool {
	if len(message.Question) != 1 || len(message.Ns) != 0 {
		return false
	}
	if len(message.Extra) == 0 {
		return !clientSubnet.IsValid()
	}
	if len(message.Extra) != 1 {
		return false
	}
	optRecord, isOPT := message.Extra[0].(*dns.OPT)
	if !isOPT || optRecord.Header().Ttl != 0 {
		return false
	}
	if !clientSubnet.IsValid() {
		return optRecord.Header().Class > 0 && len(optRecord.Option) == 0
	}
	if len(optRecord.Option) != 1 {
		return false
	}
	subnetOption, isSubnet := optRecord.Option[0].(*dns.EDNS0_SUBNET)
	if !isSubnet {
		return false
	}
	requestClientSubnet, clientSubnetValid := clientSubnetFromOption(subnetOption)
	return clientSubnetValid && requestClientSubnet == clientSubnet
}

func prepareExchangeMessage(message *dns.Msg, clientSubnet netip.Prefix) *dns.Msg {
	if clientSubnet.IsValid() {
		message = SetClientSubnet(message, clientSubnet)
	}
	return message
}

type updateDnsCacheContext struct{}

func (c *Client) UpdateDnsCacheFromContext(ctx context.Context) bool {
	_, ok := ctx.Value((*updateDnsCacheContext)(nil)).(struct{})
	return ok
}

func (c *Client) UpdateDnsCacheToContext(ctx context.Context) context.Context {
	return context.WithValue(ctx, (*updateDnsCacheContext)(nil), struct{}{})
}

func (c *Client) Exchange(ctx context.Context, transport adapter.DNSTransport, message *dns.Msg, options adapter.DNSQueryOptions, responseChecker func(responseAddrs []netip.Addr) bool) (*dns.Msg, error, bool) {
	if len(message.Question) == 0 {
		if c.logger != nil {
			c.logger.WarnContext(ctx, "bad question size: ", len(message.Question))
		}
		return FixedResponseStatus(message, dns.RcodeFormatError), nil, false
	}
	question := message.Question[0]
	if question.Qtype == dns.TypeA && options.Strategy == C.DomainStrategyIPv6Only || question.Qtype == dns.TypeAAAA && options.Strategy == C.DomainStrategyIPv4Only {
		if c.logger != nil {
			c.logger.DebugContext(ctx, "strategy rejected")
		}
		return FixedResponseStatus(message, dns.RcodeSuccess), nil, false
	}
	clientSubnet := c.effectiveClientSubnet(options)
	message = prepareExchangeMessage(message, clientSubnet)
	var isExternalClientSubnet bool
	if !clientSubnet.IsValid() {
		clientSubnet, isExternalClientSubnet = extractClientSubnet(message)
	}
	cacheKey := dnsCacheKey{Question: question, clientSubnet: clientSubnet}
	transportKey := cacheKey.withTransport(transport.Tag())
	isSimpleRequest := isSimpleDNSRequest(message, clientSubnet)
	cacheReadable := isSimpleRequest && !c.disableCache && !options.DisableCache
	cacheWritable := cacheReadable && (!isExternalClientSubnet || c.cacheClientSubnet)

	isUpdatingCache := c.UpdateDnsCacheFromContext(ctx)
	if isUpdatingCache {
		var key any
		isUpdating := func() bool {
			c.updateAccess.Lock()
			defer c.updateAccess.Unlock()
			var exist bool
			if !c.independentCache {
				_, exist = c.cacheUpdating[cacheKey]
				if !exist {
					c.cacheUpdating[cacheKey] = struct{}{}
					key = cacheKey
				}
			} else {
				_, exist = c.transportCacheUpdating[transportKey]
				if !exist {
					c.transportCacheUpdating[transportKey] = struct{}{}
					key = transportKey
				}
			}
			return exist
		}()
		if !isUpdating && key != nil {
			defer func() {
				c.updateAccess.Lock()
				defer c.updateAccess.Unlock()
				if !c.independentCache {
					delete(c.cacheUpdating, key.(dnsCacheKey))
				} else {
					delete(c.transportCacheUpdating, key.(transportCacheKey))
				}
			}()
		}
		if isUpdating {
			return nil, nil, false
		}
	}
	if cacheReadable && !isUpdatingCache {
		if cacheWritable && c.cache != nil {
			cond, loaded := c.cacheLock.LoadOrStore(transportKey, make(chan struct{}))
			if loaded {
				select {
				case <-cond:
				case <-ctx.Done():
					return nil, ctx.Err(), false
				}
			} else {
				defer func() {
					c.cacheLock.Delete(transportKey)
					close(cond)
				}()
			}
		} else if cacheWritable && c.transportCache != nil {
			cond, loaded := c.transportCacheLock.LoadOrStore(transportKey, make(chan struct{}))
			if loaded {
				select {
				case <-cond:
				case <-ctx.Done():
					return nil, ctx.Err(), false
				}
			} else {
				defer func() {
					c.transportCacheLock.Delete(transportKey)
					close(cond)
				}()
			}
		}
		response, ttl, stale := c.loadResponse(cacheKey, transport)
		if response != nil && (!stale || cacheWritable) {
			logCachedResponse(c.logger, ctx, response, ttl)
			response.Id = message.Id
			return response, nil, stale
		}
	}

	messageId := message.Id
	contextTransport, clientSubnetLoaded := transportTagFromContext(ctx)
	if clientSubnetLoaded && transport.Tag() == contextTransport {
		return nil, E.New("DNS query loopback in transport[", contextTransport, "]"), false
	}
	ctx = contextWithTransportTag(ctx, transport.Tag())
	if cacheReadable && responseChecker != nil && c.rdrc != nil {
		rejected := loadRDRC(c.rdrc, cacheKey.rdrcKey(transport.Tag()))
		if rejected {
			return nil, ErrResponseRejectedCached, false
		}
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	response, err := transport.Exchange(ctx, message)
	cancel()
	if err != nil {
		var rcodeError RcodeError
		if errors.As(err, &rcodeError) {
			response = FixedResponseStatus(message, int(rcodeError))
		} else {
			return nil, err, false
		}
	} else {
		stripDNSPadding(response)
	}
	/*if question.Qtype == dns.TypeA || question.Qtype == dns.TypeAAAA {
		validResponse := response
	loop:
		for {
			var (
				addresses  int
				queryCNAME string
			)
			for _, rawRR := range validResponse.Answer {
				switch rr := rawRR.(type) {
				case *dns.A:
					break loop
				case *dns.AAAA:
					break loop
				case *dns.CNAME:
					queryCNAME = rr.Target
				}
			}
			if queryCNAME == "" {
				break
			}
			exMessage := *message
			exMessage.Question = []dns.Question{{
				Name:  queryCNAME,
				Qtype: question.Qtype,
			}}
			validResponse, err = c.Exchange(ctx, transport, &exMessage, options, responseChecker)
			if err != nil {
				return nil, err
			}
		}
		if validResponse != response {
			response.Answer = append(response.Answer, validResponse.Answer...)
		}
	}*/
	cacheWritable = cacheWritable && (response.Rcode == dns.RcodeSuccess || response.Rcode == dns.RcodeNameError)
	if responseChecker != nil {
		var rejected bool
		// TODO: add accept_any rule and support to check response instead of addresses
		if response.Rcode != dns.RcodeSuccess && response.Rcode != dns.RcodeNameError {
			rejected = true
		} else if len(response.Answer) == 0 {
			rejected = !responseChecker(nil)
		} else {
			rejected = !responseChecker(MessageToAddresses(response))
		}
		if rejected {
			if cacheWritable && c.rdrc != nil {
				saveRDRCAsync(c.rdrc, cacheKey.rdrcKey(transport.Tag()), c.logger)
			}
			logRejectedResponse(c.logger, ctx, response)
			return response, ErrResponseRejected, false
		}
	}
	if question.Qtype == dns.TypeHTTPS {
		if options.Strategy == C.DomainStrategyIPv4Only || options.Strategy == C.DomainStrategyIPv6Only {
			for _, rr := range response.Answer {
				https, isHTTPS := rr.(*dns.HTTPS)
				if !isHTTPS {
					continue
				}
				content := https.SVCB
				content.Value = common.Filter(content.Value, func(it dns.SVCBKeyValue) bool {
					if options.Strategy == C.DomainStrategyIPv4Only {
						return it.Key() != dns.SVCB_IPV6HINT
					} else {
						return it.Key() != dns.SVCB_IPV4HINT
					}
				})
				https.SVCB = content
			}
		}
	}
	var timeToLive uint32
	if len(response.Answer) == 0 {
		if soaTTL, hasSOA := extractNegativeTTL(response); hasSOA {
			timeToLive = soaTTL
		}
	}
	if timeToLive == 0 {
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
	}
	if timeToLive < c.minCacheTTL {
		timeToLive = c.minCacheTTL
	}
	if timeToLive > c.maxCacheTTL {
		timeToLive = c.maxCacheTTL
	}
	if options.RewriteTTL != nil {
		timeToLive = *options.RewriteTTL
	}
	for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
		for _, record := range recordList {
			if record.Header().Rrtype == dns.TypeOPT {
				continue
			}
			record.Header().Ttl = timeToLive
		}
	}
	if cacheWritable {
		c.storeCache(cacheKey, transport, response, timeToLive, options.LazyCacheTTL)
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
	return response, nil, false
}

func (c *Client) Lookup(ctx context.Context, transport adapter.DNSTransport, domain string, options adapter.DNSQueryOptions, responseChecker func(responseAddrs []netip.Addr) bool) ([]netip.Addr, error, bool) {
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
	var stale4, stale6 bool
	var group task.Group
	group.Append("exchange4", func(ctx context.Context) error {
		response, err, stale := c.lookupToExchange(ctx, transport, dnsName, dns.TypeA, lookupOptions, responseChecker)
		if err != nil {
			return err
		}
		response4 = response
		stale4 = stale
		return nil
	})
	group.Append("exchange6", func(ctx context.Context) error {
		response, err, stale := c.lookupToExchange(ctx, transport, dnsName, dns.TypeAAAA, lookupOptions, responseChecker)
		if err != nil {
			return err
		}
		response6 = response
		stale6 = stale
		return nil
	})
	err := group.Run(ctx)
	if len(response4) == 0 && len(response6) == 0 {
		return nil, err, false
	}
	return sortAddresses(response4, response6, strategy), nil, stale4 || stale6
}

func (c *Client) ClearCache() {
	if c.cache != nil {
		c.cache.Purge()
	} else if c.transportCache != nil {
		c.transportCache.Purge()
	}
}

func sortAddresses(response4 []netip.Addr, response6 []netip.Addr, strategy C.DomainStrategy) []netip.Addr {
	if strategy == C.DomainStrategyPreferIPv6 {
		return append(response6, response4...)
	} else {
		return append(response4, response6...)
	}
}

func (c *Client) storeCache(key dnsCacheKey, transport adapter.DNSTransport, message *dns.Msg, timeToLive uint32, lazyCacheTTL *uint32) {
	if timeToLive == 0 {
		return
	}
	pdnsMsg := &dnsMsg{msg: message.Copy()}
	if c.disableExpire {
		if !c.independentCache {
			c.cache.Add(key, pdnsMsg)
		} else {
			c.transportCache.Add(key.withTransport(transport.Tag()), pdnsMsg)
		}
	} else {
		lifetime := time.Second * time.Duration(timeToLive)
		pdnsMsg.expireTime = time.Now().Add(lifetime)
		if lazyCacheTTL != nil {
			if *lazyCacheTTL > 0 {
				pdnsMsg.lazyCache = true
				lifetime = lifetime + (time.Second * time.Duration(*lazyCacheTTL))
			}
		} else if c.useLazyCache {
			pdnsMsg.lazyCache = true
			lifetime = lifetime + time.Second*time.Duration(c.lazyCacheTTL)
		}
		if !c.independentCache {
			c.cache.AddWithLifetime(key, pdnsMsg, lifetime)
		} else {
			c.transportCache.AddWithLifetime(key.withTransport(transport.Tag()), pdnsMsg, lifetime)
		}
	}
}

func (c *Client) lookupToExchange(ctx context.Context, transport adapter.DNSTransport, name string, qType uint16, options adapter.DNSQueryOptions, responseChecker func(responseAddrs []netip.Addr) bool) ([]netip.Addr, error, bool) {
	question := dns.Question{
		Name:   name,
		Qtype:  qType,
		Qclass: dns.ClassINET,
	}
	cacheKey := dnsCacheKey{Question: question, clientSubnet: c.effectiveClientSubnet(options)}
	isUpdatingCache := c.UpdateDnsCacheFromContext(ctx)
	disableCache := c.disableCache || options.DisableCache
	if !disableCache && !isUpdatingCache {
		cachedAddresses, err, stale := c.questionCache(cacheKey, transport)
		if err != ErrNotCached {
			return cachedAddresses, err, stale
		}
	}
	message := dns.Msg{
		MsgHdr: dns.MsgHdr{
			RecursionDesired: true,
		},
		Question: []dns.Question{question},
	}
	response, err, _ := c.Exchange(ctx, transport, &message, options, responseChecker)
	if err != nil {
		return nil, err, false
	}
	if response == nil {
		return nil, nil, false
	}
	if response.Rcode != dns.RcodeSuccess {
		return nil, RcodeError(response.Rcode), false
	}
	return MessageToAddresses(response), nil, false
}

func (c *Client) questionCache(key dnsCacheKey, transport adapter.DNSTransport) ([]netip.Addr, error, bool) {
	response, _, stale := c.loadResponse(key, transport)
	if response == nil {
		return nil, ErrNotCached, false
	}
	if response.Rcode != dns.RcodeSuccess {
		return nil, RcodeError(response.Rcode), false
	}
	return MessageToAddresses(response), nil, stale
}

func (c *Client) getRoundRobin(response *dnsMsg) *dns.Msg {
	if c.roundRobinCache {
		return response.RoundRobin()
	} else {
		return response.msg.Copy()
	}
}

func (c *Client) loadResponse(key dnsCacheKey, transport adapter.DNSTransport) (*dns.Msg, int, bool) {
	var (
		resp     *dnsMsg
		response *dns.Msg
		loaded   bool
	)
	if c.disableExpire {
		if !c.independentCache {
			resp, loaded = c.cache.Get(key)
		} else {
			resp, loaded = c.transportCache.Get(key.withTransport(transport.Tag()))
		}
		if !loaded {
			return nil, 0, false
		}
		return c.getRoundRobin(resp), 0, false
	} else {
		var expireAt time.Time
		if !c.independentCache {
			resp, expireAt, loaded = c.cache.GetWithLifetime(key)
		} else {
			resp, expireAt, loaded = c.transportCache.GetWithLifetime(key.withTransport(transport.Tag()))
		}
		if !loaded {
			return nil, 0, false
		}
		timeNow := time.Now()
		if timeNow.After(expireAt) {
			if !c.independentCache {
				c.cache.Remove(key)
			} else {
				c.transportCache.Remove(key.withTransport(transport.Tag()))
			}
			return nil, 0, false
		}
		stale := resp.lazyCache && !resp.expireTime.IsZero() && timeNow.After(resp.expireTime)
		response = c.getRoundRobin(resp)
		var originTTL int
		for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
			for _, record := range recordList {
				if record.Header().Rrtype == dns.TypeOPT {
					continue
				}
				if originTTL == 0 || record.Header().Ttl > 0 && int(record.Header().Ttl) < originTTL {
					originTTL = int(record.Header().Ttl)
				}
			}
		}
		nowTTL := max(int(expireAt.Sub(timeNow).Seconds()), 0)
		if stale {
			for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
				for _, record := range recordList {
					record.Header().Ttl = 5
				}
			}
			opt := response.IsEdns0()
			if opt == nil {
				opt = &dns.OPT{
					Hdr: dns.RR_Header{
						Name:   ".",
						Rrtype: dns.TypeOPT,
					},
				}
				opt.SetUDPSize(4096)
				response.Extra = append(response.Extra, opt)
			}
			opt.Option = append(opt.Option, &dns.EDNS0_EDE{
				InfoCode: dns.ExtendedErrorCodeStaleAnswer,
			})
			return response, 0, true
		}
		if originTTL > 0 {
			duration := uint32(originTTL - nowTTL)
			for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
				for _, record := range recordList {
					if record.Header().Rrtype == dns.TypeOPT {
						continue
					}
					record.Header().Ttl = record.Header().Ttl - duration
				}
			}
		} else {
			for _, recordList := range [][]dns.RR{response.Answer, response.Ns, response.Extra} {
				for _, record := range recordList {
					if record.Header().Rrtype == dns.TypeOPT {
						continue
					}
					record.Header().Ttl = uint32(nowTTL)
				}
			}
		}
		return response, nowTTL, false
	}
}

func MessageToAddresses(response *dns.Msg) []netip.Addr {
	if response == nil || response.Rcode != dns.RcodeSuccess {
		return nil
	}
	addresses := make([]netip.Addr, 0, len(response.Answer))
	for _, rawAnswer := range response.Answer {
		switch answer := rawAnswer.(type) {
		case *dns.A:
			addresses = append(addresses, M.AddrFromIP(answer.A))
		case *dns.AAAA:
			addresses = append(addresses, M.AddrFromIP(answer.AAAA))
		case *dns.HTTPS:
			for _, value := range answer.SVCB.Value {
				if value.Key() == dns.SVCB_IPV4HINT || value.Key() == dns.SVCB_IPV6HINT {
					addresses = append(addresses, common.Map(strings.Split(value.String(), ","), M.ParseAddr)...)
				}
			}
		}
	}
	return addresses
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
