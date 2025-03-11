package outbound

import (
	"context"
	"os"
	"slices"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"
)

var _ adapter.OutboundManager = (*Manager)(nil)

type Manager struct {
	mutation         sync.Mutex
	lifecycle        *adapter.LifecycleGroup
	stage            adapter.StartStage
	referenceTracker adapter.DomainResolverReferenceTracker

	registry           adapter.OutboundRegistry
	endpoint           adapter.EndpointManager
	defaultTag         string
	access             sync.RWMutex
	outbounds          []adapter.Outbound
	outboundByTag      map[string]adapter.Outbound
	defaultOutbound    adapter.Outbound
	compatibleOutbound adapter.Outbound
}

func NewManager(registry adapter.OutboundRegistry, endpoint adapter.EndpointManager, defaultTag string) *Manager {
	return &Manager{
		registry:      registry,
		endpoint:      endpoint,
		defaultTag:    defaultTag,
		outboundByTag: make(map[string]adapter.Outbound),
	}
}

func (m *Manager) RegisterCompatible(outbound adapter.Outbound) {
	m.access.Lock()
	m.compatibleOutbound = outbound
	m.access.Unlock()
}

func (m *Manager) Initialize(defaultOutboundFallback func() (adapter.Outbound, error)) error {
	m.access.Lock()
	if m.defaultTag != "" && m.defaultOutbound == nil {
		if defaultOutbound, loaded := m.outboundByTag[m.defaultTag]; loaded {
			m.defaultOutbound = defaultOutbound
		} else if defaultEndpoint, loaded := m.endpoint.Get(m.defaultTag); loaded {
			m.defaultOutbound = defaultEndpoint
		} else if m.defaultTag == "Compatible" && m.compatibleOutbound != nil {
			m.defaultOutbound = m.compatibleOutbound
		} else {
			m.access.Unlock()
			return E.New("default outbound not found: ", m.defaultTag)
		}
	}
	if m.defaultOutbound == nil {
		directOutbound, err := defaultOutboundFallback()
		if err != nil {
			m.access.Unlock()
			return E.Cause(err, "create direct outbound for fallback")
		}
		m.outbounds = append(m.outbounds, directOutbound)
		m.outboundByTag[directOutbound.Tag()] = directOutbound
		m.defaultOutbound = directOutbound
	}
	m.access.Unlock()
	_, err := sortOutbounds(m.collectOutboundsForSort())
	return err
}

func (m *Manager) collectOutboundsForSort() []adapter.Outbound {
	m.access.RLock()
	outbounds := append([]adapter.Outbound(nil), m.outbounds...)
	compatible := m.compatibleOutbound
	_, hasCompatibleOutbound := m.outboundByTag["Compatible"]
	m.access.RUnlock()
	endpoints := m.endpoint.Endpoints()
	hasCompatibleEndpoint := false
	for _, ep := range endpoints {
		if ep.Tag() == "Compatible" {
			hasCompatibleEndpoint = true
			break
		}
	}
	combined := slices.Concat(outbounds, common.Map(endpoints, func(it adapter.Endpoint) adapter.Outbound { return it }))
	if compatible != nil && !hasCompatibleOutbound && !hasCompatibleEndpoint {
		combined = append(combined, compatible)
	}
	return combined
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	m.stage = stage
	if stage == adapter.StartStateInitialize {
		m.lifecycle = adapter.NewLifecycleGroup(scope)
		m.referenceTracker = service.FromContext[adapter.DomainResolverReferenceTracker](scope.Context())
	}
	sortedOutbounds, err := sortOutbounds(m.collectOutboundsForSort())
	if err != nil {
		return err
	}
	for _, outbound := range sortedOutbounds {
		if endpoint, isEndpoint := outbound.(adapter.Endpoint); isEndpoint {
			if stage == adapter.StartStateStart {
				err := m.endpoint.StartEndpoint(endpoint)
				if err != nil {
					return err
				}
			}
			continue
		}
		lifecycle, isLifecycle := outbound.(adapter.Lifecycle)
		if !isLifecycle {
			continue
		}
		name := "outbound/" + outbound.Type() + "[" + outbound.Tag() + "]"
		err = m.lifecycle.Start(name, lifecycle, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func sortOutbounds(outbounds []adapter.Outbound) ([]adapter.Outbound, error) {
	sortedOutbounds := make([]adapter.Outbound, 0, len(outbounds))
	sorted := make(map[string]bool)
	for {
		canContinue := false
	sortOne:
		for _, outboundToSort := range outbounds {
			outboundTag := outboundToSort.Tag()
			if sorted[outboundTag] {
				continue
			}
			dependencies := outboundToSort.Dependencies()
			for _, dependency := range dependencies {
				if !sorted[dependency] {
					continue sortOne
				}
			}
			sorted[outboundTag] = true
			canContinue = true
			sortedOutbounds = append(sortedOutbounds, outboundToSort)
		}
		if len(sorted) == len(outbounds) {
			break
		}
		if canContinue {
			continue
		}
		currentOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
			return !sorted[it.Tag()]
		})
		var lintOutbound func(oTree []string, oCurrent adapter.Outbound) error
		lintOutbound = func(oTree []string, oCurrent adapter.Outbound) error {
			problemOutboundTag := common.Find(oCurrent.Dependencies(), func(it string) bool {
				return !sorted[it]
			})
			if common.Contains(oTree, problemOutboundTag) {
				return E.New("circular outbound dependency: ", strings.Join(oTree, " -> "), " -> ", problemOutboundTag)
			}
			problemOutbound := common.Find(outbounds, func(it adapter.Outbound) bool {
				return it.Tag() == problemOutboundTag
			})
			if problemOutbound == nil {
				return E.New("dependency[", problemOutboundTag, "] not found for outbound[", oCurrent.Tag(), "]")
			}
			return lintOutbound(append(oTree, problemOutboundTag), problemOutbound)
		}
		return nil, lintOutbound([]string{currentOutbound.Tag()}, currentOutbound)
	}
	return sortedOutbounds, nil
}

func (m *Manager) Outbounds() []adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return append([]adapter.Outbound(nil), m.outbounds...)
}

func (m *Manager) Outbound(tag string) (adapter.Outbound, bool) {
	m.access.RLock()
	outbound, found := m.outboundByTag[tag]
	compatible := m.compatibleOutbound
	m.access.RUnlock()
	if found {
		return outbound, true
	}
	if endpoint, loaded := m.endpoint.Get(tag); loaded {
		return endpoint, true
	}
	if tag == "Compatible" && compatible != nil {
		return compatible, true
	}
	return nil, false
}

func (m *Manager) Default() adapter.Outbound {
	m.access.RLock()
	defer m.access.RUnlock()
	return m.defaultOutbound
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, inboundType string, options any) error {
	if tag == "" {
		return os.ErrInvalid
	}
	outbound, err := m.registry.CreateOutbound(ctx, router, logger, tag, inboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	_, loaded := m.outboundByTag[tag]
	if loaded {
		return E.New("duplicate outbound tag: ", tag)
	}
	m.outbounds = append(m.outbounds, outbound)
	m.outboundByTag[tag] = outbound
	if tag == m.defaultTag || (m.defaultTag == "" && m.defaultOutbound == nil) {
		m.defaultOutbound = outbound
	}
	return nil
}

// Replace prepares a provider node before publishing it. Static Create retains
// its duplicate-tag validation.
func (m *Manager) Replace(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	node, err := m.registry.CreateOutbound(ctx, router, logger, tag, outboundType, options)
	if err != nil {
		return err
	}
	if lifecycle, ok := node.(adapter.Lifecycle); ok && m.lifecycle != nil {
		for _, stage := range adapter.ListStartStages {
			if stage > m.stage {
				break
			}
			if err = m.lifecycle.Start("outbound/"+node.Type()+"["+tag+"]", lifecycle, stage); err != nil {
				return E.Errors(err, m.lifecycle.Remove(lifecycle))
			}
		}
	}
	m.access.Lock()
	old := m.outboundByTag[tag]
	if old == nil {
		m.outbounds = append(m.outbounds, node)
	} else {
		for i, item := range m.outbounds {
			if item == old {
				m.outbounds[i] = node
				break
			}
		}
	}
	m.outboundByTag[tag] = node
	if m.defaultOutbound == old && old != nil {
		m.defaultOutbound = node
	}
	m.access.Unlock()
	if m.referenceTracker == nil {
		m.referenceTracker = service.FromContext[adapter.DomainResolverReferenceTracker](ctx)
	}
	if m.referenceTracker != nil {
		m.referenceTracker.UpdateDomainResolvers(tag, false, options)
	}
	if lifecycle, ok := old.(adapter.Lifecycle); ok && m.lifecycle != nil {
		if closeErr := m.lifecycle.Remove(lifecycle); closeErr != nil {
			logger.Error(closeErr, "close replaced outbound ", tag)
		}
	}
	return nil
}

func (m *Manager) Remove(tag string) error {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	m.access.Lock()
	old := m.outboundByTag[tag]
	if old == nil {
		m.access.Unlock()
		return nil
	}
	delete(m.outboundByTag, tag)
	for i, item := range m.outbounds {
		if item == old {
			m.outbounds = append(m.outbounds[:i], m.outbounds[i+1:]...)
			break
		}
	}
	if m.defaultOutbound == old {
		m.defaultOutbound = nil
		if len(m.outbounds) > 0 {
			m.defaultOutbound = m.outbounds[0]
		}
	}
	m.access.Unlock()
	if m.referenceTracker != nil {
		m.referenceTracker.RemoveDomainResolvers(tag, false)
	}
	if lifecycle, ok := old.(adapter.Lifecycle); ok && m.lifecycle != nil {
		return m.lifecycle.Remove(lifecycle)
	}
	return nil
}
