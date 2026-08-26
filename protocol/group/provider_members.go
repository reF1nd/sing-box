package group

import (
	"context"
	"regexp"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	U "github.com/sagernet/sing-box/common/urltest"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
)

type outboundURLTestResult struct {
	delay uint16
	err   error
}

func urlTestOutbound(ctx context.Context, link string, outbound adapter.Outbound) (uint16, error) {
	testCtx, cancel := context.WithTimeout(ctx, C.TCPTimeout)
	defer cancel()
	result := make(chan outboundURLTestResult, 1)
	go func() {
		delay, err := U.URLTest(testCtx, link, outbound)
		result <- outboundURLTestResult{delay, err}
	}()
	select {
	case testResult := <-result:
		return testResult.delay, testResult.err
	case <-testCtx.Done():
		return 0, testCtx.Err()
	}
}

type providerUpdateCheckScheduler struct {
	access  sync.Mutex
	running bool
	pending bool
}

func (c *providerUpdateCheckScheduler) Schedule(check func()) {
	c.access.Lock()
	c.pending = true
	if c.running {
		c.access.Unlock()
		return
	}
	c.running = true
	c.access.Unlock()
	go func() {
		for {
			c.access.Lock()
			c.pending = false
			c.access.Unlock()
			check()
			c.access.Lock()
			if !c.pending {
				c.running = false
				c.access.Unlock()
				return
			}
			c.access.Unlock()
		}
	}()
}

func collectProviderOutbounds(
	updatedTag string,
	directTags []string,
	outboundManager adapter.OutboundManager,
	providers map[string]adapter.Provider,
	providerTags []string,
	outboundsCache map[string][]adapter.Outbound,
	exclude *regexp.Regexp,
	include *regexp.Regexp,
) ([]string, []adapter.Outbound, map[string][]adapter.Outbound, error) {
	if _, loaded := providers[updatedTag]; !loaded {
		return nil, nil, nil, E.New("outbound provider not found: ", updatedTag)
	}
	newCache := make(map[string][]adapter.Outbound, len(outboundsCache))
	for providerTag, cachedOutbounds := range outboundsCache {
		newCache[providerTag] = cachedOutbounds
	}
	var (
		tags      = make([]string, 0, len(directTags))
		outbounds = make([]adapter.Outbound, 0, len(directTags))
	)
	for i, tag := range directTags {
		detour, loaded := outboundManager.Outbound(tag)
		if !loaded {
			return nil, nil, nil, E.New("outbound ", i, " not found: ", tag)
		}
		tags = append(tags, tag)
		outbounds = append(outbounds, detour)
	}
	for _, providerTag := range providerTags {
		if providerTag != updatedTag {
			if cachedOutbounds := newCache[providerTag]; cachedOutbounds != nil {
				for _, detour := range cachedOutbounds {
					tags = append(tags, detour.Tag())
				}
				outbounds = append(outbounds, cachedOutbounds...)
				continue
			}
		}
		provider := providers[providerTag]
		if provider == nil {
			return nil, nil, nil, E.New("outbound provider not found: ", providerTag)
		}
		cachedOutbounds := make([]adapter.Outbound, 0)
		for _, detour := range provider.Outbounds() {
			tag := detour.Tag()
			if exclude != nil && exclude.MatchString(tag) {
				continue
			}
			if include != nil && !include.MatchString(tag) {
				continue
			}
			tags = append(tags, tag)
			outbounds = append(outbounds, detour)
			cachedOutbounds = append(cachedOutbounds, detour)
		}
		newCache[providerTag] = cachedOutbounds
	}
	if len(tags) == 0 {
		detour, loaded := outboundManager.Outbound("Compatible")
		if !loaded {
			return nil, nil, nil, E.New("fallback outbound not found: Compatible")
		}
		tags = append(tags, detour.Tag())
		outbounds = append(outbounds, detour)
	}
	return tags, outbounds, newCache, nil
}
