//go:build with_outbound_provider

package outboundprovider

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/outbound"
	"github.com/sagernet/sing-box/outboundprovider/parse"
	"github.com/sagernet/sing/common/batch"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

const DefaultHealthCheckTimeout = time.Second * 30

var (
	DefaultUserAgent      string
	regTraffic, regExpire *regexp.Regexp
)

func init() {
	DefaultUserAgent = fmt.Sprintf(
		"clash; clash-meta; meta; sing/%s; sing-box/%s; SFA/%s; SFI/%s; SFT/%s; SFM/%s",
		C.Version,
		C.Version,
		C.Version,
		C.Version,
		C.Version,
		C.Version,
	)
	regTraffic = regexp.MustCompile(`upload=(\d+); download=(\d+); total=(\d+)`)
	regExpire = regexp.MustCompile(`expire=(\d+)`)
}

var _ adapter.OutboundProvider = (*OutboundProvider)(nil)

type OutboundProvider struct {
	ctx                  context.Context
	router               adapter.Router
	logFactory           log.Factory
	logger               log.ContextLogger
	tag                  string
	cacheTag             string
	url                  string
	updateInterval       time.Duration
	requestTimeout       time.Duration
	http3                bool
	header               http.Header
	selectorOptions      option.SelectorOutboundOptions
	optimize             bool
	dialer               N.Dialer
	dependentOutboundTag string
	actions              []action
	httpClient           *http.Client
	cacheFile            adapter.CacheFile
	cacheData            adapter.OutboundProviderData
	//
	basicOutbounds     []adapter.Outbound
	basicOutboundByTag map[string]adapter.Outbound
	groupOutbounds     []adapter.Outbound
	groupOutboundByTag map[string]adapter.Outbound
	globalOutbound     adapter.Outbound
	cacheOutbounds     []adapter.Outbound
	//
	updateLock    sync.Mutex
	loopCtx       context.Context
	loopCancel    context.CancelFunc
	loopCloseDone chan struct{}
	started       bool
}

func New(ctx context.Context, router adapter.Router, logFactory log.Factory, logger log.ContextLogger, tag string, options option.OutboundProvider) (adapter.OutboundProvider, error) {
	p := &OutboundProvider{
		ctx:             ctx,
		router:          router,
		logFactory:      logFactory,
		logger:          logger,
		tag:             tag,
		url:             options.URL,
		cacheTag:        options.CacheTag,
		updateInterval:  time.Duration(options.UpdateInterval),
		requestTimeout:  time.Duration(options.RequestTimeout),
		http3:           options.HTTP3,
		header:          make(http.Header),
		selectorOptions: options.SelectorOptions,
		optimize:        options.Optimize,
	}
	if p.url == "" {
		return nil, E.New("missing url")
	}
	if p.cacheTag == "" {
		p.cacheTag = p.tag
	}
	p.header.Set("User-Agent", DefaultUserAgent)
	if len(options.Headers) > 0 {
		for k, v := range options.Headers {
			p.header.Set(k, v)
		}
	}
	d, err := dialer.New(router, options.DialerOptions)
	if err != nil {
		return nil, err
	}
	p.dialer = d
	p.dependentOutboundTag = options.Detour
	if len(options.Actions) > 0 {
		p.actions = make([]action, 0, len(options.Actions))
		for i, actionOptions := range options.Actions {
			a, err := newAction(actionOptions)
			if err != nil {
				return nil, E.Cause(err, "parse action[", i, "] failed")
			}
			p.actions = append(p.actions, a)
		}
	}
	return p, nil
}

func (p *OutboundProvider) Tag() string {
	return p.tag
}

func (p *OutboundProvider) DependentOutbound() string {
	return p.dependentOutboundTag
}

func (p *OutboundProvider) PreStart() error {
	p.initCacheFile()
	var data adapter.OutboundProviderData
	if p.cacheFile != nil {
		data, _ = p.loadFromCache()
	}
	if data.Outbounds == nil || (p.updateInterval > 0 && time.Since(data.SubscribeData.Update) > p.updateInterval) {
		var err error
		data, err = p.fetch(p.ctx)
		if err != nil && data.Outbounds == nil {
			return E.Cause(err, "fetch failed")
		}
		if err != nil {
			p.logger.Warn("fetch failed: ", err, ", use cache")
		}
		err = p.saveToCache(data)
		if err != nil {
			p.logger.Warn("save to cache failed: ", err)
		}
	}
	p.cacheData = data
	basicOutbounds, groupOutbounds, globalOutbound, err := p.newOutbounds(data.Outbounds)
	p.cacheData.Outbounds = nil
	if err != nil {
		return E.Cause(err, "create outbounds failed")
	}
	var (
		basicOutboundByTag = make(map[string]adapter.Outbound, len(basicOutbounds))
		groupOutboundByTag = make(map[string]adapter.Outbound, len(groupOutbounds))
	)
	for _, outbound := range basicOutbounds {
		basicOutboundByTag[outbound.Tag()] = outbound
	}
	for _, outbound := range groupOutbounds {
		groupOutboundByTag[outbound.Tag()] = outbound
	}
	p.basicOutbounds = basicOutbounds
	p.basicOutboundByTag = basicOutboundByTag
	p.groupOutbounds = groupOutbounds
	p.groupOutboundByTag = groupOutboundByTag
	p.globalOutbound = globalOutbound
	return nil
}

func (p *OutboundProvider) Start() error {
	if p.updateInterval > 0 && p.loopCtx == nil {
		p.loopCtx, p.loopCancel = context.WithCancel(p.ctx)
		p.loopCloseDone = make(chan struct{}, 1)
		go p.loopUpdate()
	}
	return nil
}

func (p *OutboundProvider) Close() error {
	if p.updateInterval > 0 && p.loopCancel != nil {
		p.loopCancel()
		<-p.loopCloseDone
		close(p.loopCloseDone)
	}
	return nil
}

func (p *OutboundProvider) Outbounds() []adapter.Outbound {
	outbounds := p.cacheOutbounds
	if len(outbounds) == 0 {
		outbounds = make([]adapter.Outbound, 0, len(p.basicOutbounds)+len(p.groupOutbounds)+1)
		outbounds = append(outbounds, p.basicOutbounds...)
		outbounds = append(outbounds, p.groupOutbounds...)
		if p.globalOutbound != nil {
			outbounds = append(outbounds, p.globalOutbound)
		}
		p.cacheOutbounds = outbounds
	}
	return outbounds
}

func (p *OutboundProvider) BasicOutbounds() []adapter.Outbound {
	if p.optimize {
		basicOutbounds := make([]adapter.Outbound, 0, len(p.basicOutbounds))
		for _, outbound := range p.basicOutbounds {
			switch outbound.Type() {
			case C.TypeDNS:
			case C.TypeBlock:
			case C.TypeShadowTLS:
			default:
				basicOutbounds = append(basicOutbounds, outbound)
			}
		}
		return basicOutbounds
	} else {
		return p.basicOutbounds
	}
}

func (p *OutboundProvider) FilterOutbounds(matcher adapter.OutboundMatcher, invert bool) []adapter.Outbound {
	outbounds := make([]adapter.Outbound, 0, len(p.basicOutbounds)+len(p.groupOutbounds))
	outbounds = append(outbounds, p.basicOutbounds...)
	outbounds = append(outbounds, p.groupOutbounds...)
	filterOutbounds := make([]adapter.Outbound, 0, len(outbounds))
	for _, outbound := range outbounds {
		if !invert {
			if matcher.MatchOutbound(outbound) {
				filterOutbounds = append(filterOutbounds, outbound)
			}
		} else {
			if !matcher.MatchOutbound(outbound) {
				filterOutbounds = append(filterOutbounds, outbound)
			}
		}
	}
	return filterOutbounds
}

func (p *OutboundProvider) Outbound(tag string) (adapter.Outbound, bool) {
	if p.globalOutbound != nil && p.globalOutbound.Tag() == tag {
		return p.globalOutbound, true
	}
	if p.basicOutboundByTag != nil {
		outbound, loaded := p.basicOutboundByTag[tag]
		if loaded {
			return outbound, true
		}
	}
	if p.groupOutboundByTag != nil {
		outbound, loaded := p.groupOutboundByTag[tag]
		if loaded {
			return outbound, true
		}
	}
	return nil, false
}

func (p *OutboundProvider) Update() {
	go func() {
		if p.updateLock.TryLock() {
			p.update(p.ctx)
			p.updateLock.Unlock()
		}
	}()
}

func (p *OutboundProvider) GetSubsctibeData() adapter.OutboundProviderSubscribeData {
	return p.cacheData.SubscribeData
}

func (p *OutboundProvider) HealthCheck() {
	urlTestHistoryStroage := service.PtrFromContext[urltest.HistoryStorage](p.ctx)
	if urlTestHistoryStroage == nil {
		clashServer := p.router.ClashServer()
		if clashServer != nil {
			urlTestHistoryStroage = clashServer.HistoryStorage()
		}
	}
	if urlTestHistoryStroage == nil {
		return
	}
	outbounds := p.basicOutbounds
	ctx, cancel := context.WithTimeout(p.ctx, DefaultHealthCheckTimeout)
	defer cancel()
	b, _ := batch.New(ctx, batch.WithConcurrencyNum[*struct{}](10))
	var (
		outboundMap  = make(map[string]uint16, len(outbounds))
		outboundLock sync.Mutex
	)
	for _, out := range outbounds {
		switch out.Type() {
		case C.TypeDNS, C.TypeShadowTLS, C.TypeBlock, C.TypeSelector, C.TypeURLTest:
			continue
		}
		detour := out
		b.Go(out.Tag(), func() (*struct{}, error) {
			delay, err := urltest.URLTest(ctx, "", detour)
			if err != nil {
				urlTestHistoryStroage.DeleteURLTestHistory(detour.Tag())
			} else {
				urlTestHistoryStroage.StoreURLTestHistory(detour.Tag(), &urltest.History{
					Time:  time.Now(),
					Delay: delay,
				})
				outboundLock.Lock()
				outboundMap[detour.Tag()] = delay
				outboundLock.Unlock()
			}
			return nil, nil
		})
	}
	b.Wait()
	for _, out := range outbounds {
		switch out.Type() {
		case C.TypeSelector, C.TypeURLTest:
			realTag := outbound.RealTag(out)
			delay, loaded := outboundMap[realTag]
			if loaded {
				urlTestHistoryStroage.StoreURLTestHistory(out.Tag(), &urltest.History{
					Time:  time.Now(),
					Delay: delay,
				})
			}
		}
	}
}

func (p *OutboundProvider) newOutbounds(outboundOptions []option.Outbound) ([]adapter.Outbound, []adapter.Outbound, adapter.Outbound, error) { // basicOutbound, groupOutbound, globalOutbound
	processor := newProcessor(outboundOptions)
	var err error
	for i, action := range p.actions {
		err = action.apply(p.ctx, p.router, p.logger, processor)
		if err != nil {
			return nil, nil, nil, E.Cause(err, "apply action[", i, "] failed")
		}
	}
	basicOutboundOptions := processor.BasicOutbounds()
	if len(basicOutboundOptions) == 0 {
		return nil, nil, nil, E.New("missing basic outbound")
	}
	groupOutboundOptions := processor.GroupOutbounds()
	globalOutboundOptions := option.Outbound{
		Tag:             p.tag,
		Type:            C.TypeSelector,
		SelectorOptions: p.selectorOptions,
	}
	outboundTags := make([]string, 0, len(globalOutboundOptions.SelectorOptions.Outbounds)+len(basicOutboundOptions)+len(groupOutboundOptions))
	if len(globalOutboundOptions.SelectorOptions.Outbounds) > 0 {
		outboundTags = append(outboundTags, globalOutboundOptions.SelectorOptions.Outbounds...)
	}
	if p.optimize {
		for _, outbound := range basicOutboundOptions {
			switch outbound.Type {
			case C.TypeDNS:
			case C.TypeBlock:
			case C.TypeShadowTLS:
			default:
				outboundTags = append(outboundTags, outbound.Tag)
			}
		}
	} else {
		for _, outbound := range basicOutboundOptions {
			outboundTags = append(outboundTags, outbound.Tag)
		}
	}
	for _, outbound := range groupOutboundOptions {
		outboundTags = append(outboundTags, outbound.Tag)
	}
	globalOutboundOptions.SelectorOptions.Outbounds = outboundTags
	// create outbounds
	var (
		basicOutbounds = make([]adapter.Outbound, 0, len(basicOutboundOptions))
		groupOutbounds = make([]adapter.Outbound, 0, len(groupOutboundOptions))
	)
	for i, outboundOptions := range basicOutboundOptions {
		var out adapter.Outbound
		out, err = outbound.New(
			p.ctx,
			p.router,
			p.logFactory.NewLogger(F.ToString("outbound/", outboundOptions.Type, "[", outboundOptions.Tag, "]")),
			outboundOptions.Tag,
			outboundOptions)
		if err != nil {
			return nil, nil, nil, E.Cause(err, "parse basic outbound[", i, "]")
		}
		basicOutbounds = append(basicOutbounds, out)
	}
	for i, outboundOptions := range groupOutboundOptions {
		var out adapter.Outbound
		out, err = outbound.New(
			p.ctx,
			p.router,
			p.logFactory.NewLogger(F.ToString("outbound/", outboundOptions.Type, "[", outboundOptions.Tag, "]")),
			outboundOptions.Tag,
			outboundOptions)
		if err != nil {
			return nil, nil, nil, E.Cause(err, "parse group outbound[", i, "]")
		}
		groupOutbounds = append(groupOutbounds, out)
	}
	var globalOutbound adapter.Outbound
	globalOutbound, err = outbound.New(
		p.ctx,
		p.router,
		p.logFactory.NewLogger(F.ToString("outbound/", globalOutboundOptions.Type, "[", globalOutboundOptions.Tag, "]")),
		globalOutboundOptions.Tag,
		globalOutboundOptions)
	if err != nil {
		return nil, nil, nil, E.Cause(err, "parse global outbound[", globalOutboundOptions.Tag, "]")
	}
	return basicOutbounds, groupOutbounds, globalOutbound, nil
}

func (p *OutboundProvider) loopUpdate() {
	defer func() {
		p.loopCloseDone <- struct{}{}
	}()
	ticker := time.NewTicker(p.updateInterval)
	defer ticker.Stop()
	for {
		select {
		case <-p.loopCtx.Done():
			return
		case <-ticker.C:
			if p.updateLock.TryLock() {
				p.update(p.loopCtx)
				p.updateLock.Unlock()
			}
		}
	}
}

func (p *OutboundProvider) update(ctx context.Context) {
	p.logger.Info("update...")
	defer p.logger.Info("update done")
	if ctx == nil {
		ctx = p.ctx
	}
	data, err := p.fetch(ctx)
	if err != nil {
		p.logger.Error("update: fetch failed: ", err)
		return
	}
	err = p.saveToCache(data)
	if err != nil {
		p.logger.Error("update: save to cache failed: ", err)
		return
	}
	data.Outbounds = nil
	p.cacheData = data
	// TODO: update outbounds
	p.logger.Info("update success")
}

func (p *OutboundProvider) fetch(ctx context.Context) (adapter.OutboundProviderData, error) {
	httpClient := p.httpClient
	if httpClient == nil {
		if !p.http3 {
			httpClient = &http.Client{
				Transport: &http.Transport{
					ForceAttemptHTTP2: true,
					DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
						return p.dialer.DialContext(ctx, network, M.ParseSocksaddr(address))
					},
				},
			}
		} else {
			httpClient = &http.Client{
				Transport: &http3.RoundTripper{
					Dial: func(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (quic.EarlyConnection, error) {
						destinationAddr := M.ParseSocksaddr(address)
						conn, err := p.dialer.DialContext(ctx, N.NetworkUDP, destinationAddr)
						if err != nil {
							return nil, err
						}
						return quic.DialEarly(ctx, bufio.NewUnbindPacketConn(conn), conn.RemoteAddr(), tlsConfig, quicConfig)
					},
				},
			}
		}
		p.httpClient = httpClient
	}
	if p.requestTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.requestTimeout)
		defer cancel()
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodGet, p.url, nil)
	if err != nil {
		return adapter.OutboundProviderData{}, err
	}
	for k, v := range p.header {
		httpReq.Header[k] = v
	}
	httpResp, err := httpClient.Do(httpReq)
	if err != nil {
		return adapter.OutboundProviderData{}, err
	}
	buffer := bytes.NewBuffer(nil)
	_, err = io.Copy(buffer, httpResp.Body)
	httpResp.Body.Close()
	if err != nil {
		return adapter.OutboundProviderData{}, err
	}
	outbounds, err := parse.ParseConfig(buffer.Bytes())
	if err != nil {
		return adapter.OutboundProviderData{}, err
	}
	data := adapter.OutboundProviderData{
		Outbounds: outbounds,
	}
	data.SubscribeData.Update = time.Now()
	subscriptionUserInfo := httpResp.Header.Get("subscription-userinfo")
	if subscriptionUserInfo != "" {
		subscriptionUserInfo = strings.ToLower(subscriptionUserInfo)
		matchTraffic := regTraffic.FindStringSubmatch(subscriptionUserInfo)
		if len(matchTraffic) == 4 {
			uploadUint64, err := strconv.ParseUint(matchTraffic[1], 10, 64)
			if err == nil {
				data.SubscribeData.Upload = uploadUint64
			}
			downloadUint64, err := strconv.ParseUint(matchTraffic[2], 10, 64)
			if err == nil {
				data.SubscribeData.Download = downloadUint64
			}
			totalUint64, err := strconv.ParseUint(matchTraffic[3], 10, 64)
			if err == nil {
				data.SubscribeData.Total = totalUint64
			}
		}
		matchExpire := regExpire.FindStringSubmatch(subscriptionUserInfo)
		if len(matchExpire) == 2 {
			expireUint64, err := strconv.ParseUint(matchExpire[1], 10, 64)
			if err == nil {
				data.SubscribeData.Expire = time.Unix(int64(expireUint64), 0)
			}
		}
	}
	return data, nil
}

func (p *OutboundProvider) initCacheFile() {
	if p.cacheFile == nil {
		p.cacheFile = service.FromContext[adapter.CacheFile](p.ctx)
	}
}

func (p *OutboundProvider) saveToCache(data adapter.OutboundProviderData) error {
	cacheFile := p.cacheFile
	if cacheFile == nil {
		return nil
	}
	return cacheFile.StoreOutboundProviderData(p.cacheTag, data)
}

func (p *OutboundProvider) loadFromCache() (adapter.OutboundProviderData, error) {
	cacheFile := p.cacheFile
	if cacheFile == nil {
		return adapter.OutboundProviderData{}, nil
	}
	return cacheFile.LoadOutboundProviderData(p.cacheTag)
}
