package group

import (
	"maps"
	"regexp"
	"slices"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	E "github.com/sagernet/sing/common/exceptions"
)

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
	selfTag string,
	updatedTag string,
	directTags []string,
	outboundManager adapter.OutboundManager,
	providers map[string]adapter.Provider,
	providerTags []string,
	outboundsCache map[string][]adapter.Outbound,
	exclude *regexp.Regexp,
	include *regexp.Regexp,
) ([]string, []adapter.Outbound, map[string][]adapter.Outbound, error) {
	// An empty updatedTag reads every provider without a cached snapshot.
	if updatedTag != "" {
		if _, loaded := providers[updatedTag]; !loaded {
			return nil, nil, nil, E.New("outbound provider not found: ", updatedTag)
		}
	}
	newCache := make(map[string][]adapter.Outbound, len(outboundsCache))
	maps.Copy(newCache, outboundsCache)
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
			if selfTag != "" && tag == selfTag {
				continue
			}
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
		if selfTag != "" && referencesOutboundTag(outboundManager, detour, selfTag, make(map[string]bool)) {
			if detour.Tag() == selfTag {
				return nil, nil, nil, E.New("fallback outbound Compatible cannot reference itself")
			}
			return nil, nil, nil, E.New("fallback outbound Compatible cannot reference ", selfTag)
		}
		tags = append(tags, detour.Tag())
		outbounds = append(outbounds, detour)
	}
	return tags, outbounds, newCache, nil
}

func referencesOutboundTag(outboundManager adapter.OutboundManager, current adapter.Outbound, targetTag string, visited map[string]bool) bool {
	if current == nil || targetTag == "" {
		return false
	}
	tag := current.Tag()
	if tag == targetTag {
		return true
	}
	if tag != "" {
		if visited[tag] {
			return false
		}
		visited[tag] = true
	}
	group, isGroup := current.(adapter.OutboundGroup)
	if !isGroup {
		return false
	}
	for _, depTag := range group.Dependencies() {
		if depTag == targetTag {
			return true
		}
		if dep, loaded := outboundManager.Outbound(depTag); loaded && referencesOutboundTag(outboundManager, dep, targetTag, visited) {
			return true
		}
	}
	for _, memberTag := range group.All() {
		if memberTag == targetTag {
			return true
		}
		if member, loaded := outboundManager.Outbound(memberTag); loaded && referencesOutboundTag(outboundManager, member, targetTag, visited) {
			return true
		}
	}
	return false
}

// providerDependencies returns static dependencies plus any members bound
// providers already hold, so outbound startup starts inline provider members
// (such as nested groups) before groups that expose them.
func providerDependencies(
	selfTag string,
	directTags []string,
	providerManager adapter.ProviderManager,
	providerTags []string,
	useAllProviders bool,
	exclude *regexp.Regexp,
	include *regexp.Regexp,
) []string {
	if providerManager == nil || (!useAllProviders && len(providerTags) == 0) {
		return directTags
	}
	var providers []adapter.Provider
	if useAllProviders {
		providers = providerManager.Providers()
	} else {
		providers = make([]adapter.Provider, 0, len(providerTags))
		for _, providerTag := range providerTags {
			if provider, loaded := providerManager.Get(providerTag); loaded {
				providers = append(providers, provider)
			}
		}
	}
	if len(providers) == 0 {
		return directTags
	}
	var dependencies []string
	for _, provider := range providers {
		for _, detour := range provider.Outbounds() {
			tag := detour.Tag()
			if tag == "" || tag == selfTag {
				continue
			}
			if exclude != nil && exclude.MatchString(tag) {
				continue
			}
			if include != nil && !include.MatchString(tag) {
				continue
			}
			if dependencies == nil {
				dependencies = slices.Clone(directTags)
			}
			if !slices.Contains(dependencies, tag) {
				dependencies = append(dependencies, tag)
			}
		}
	}
	if dependencies == nil {
		return directTags
	}
	return dependencies
}
