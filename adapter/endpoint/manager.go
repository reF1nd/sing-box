package endpoint

import (
	"context"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	E "github.com/sagernet/sing/common/exceptions"
)

var _ adapter.EndpointManager = (*Manager)(nil)

type Manager struct {
	mutation  sync.Mutex
	lifecycle *adapter.LifecycleGroup
	stage     adapter.StartStage

	registry      adapter.EndpointRegistry
	access        sync.Mutex
	endpoints     []adapter.Endpoint
	endpointByTag map[string]adapter.Endpoint
}

func NewManager(registry adapter.EndpointRegistry) *Manager {
	return &Manager{
		registry:      registry,
		endpointByTag: make(map[string]adapter.Endpoint),
	}
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	m.stage = stage
	if stage == adapter.StartStateInitialize {
		m.lifecycle = adapter.NewLifecycleGroup(scope)
	}
	m.access.Lock()
	endpoints := append([]adapter.Endpoint(nil), m.endpoints...)
	m.access.Unlock()
	if stage == adapter.StartStateStart {
		return nil
	}
	for _, endpoint := range endpoints {
		name := "endpoint/" + endpoint.Type() + "[" + endpoint.Tag() + "]"
		err := m.lifecycle.Start(name, endpoint, stage)
		if err != nil {
			return err
		}
	}
	return nil
}

func (m *Manager) StartEndpoint(endpoint adapter.Endpoint) error {
	return m.lifecycle.Start("endpoint/"+endpoint.Type()+"["+endpoint.Tag()+"]", endpoint, adapter.StartStateStart)
}

func (m *Manager) Endpoints() []adapter.Endpoint {
	m.access.Lock()
	defer m.access.Unlock()
	return append([]adapter.Endpoint(nil), m.endpoints...)
}

func (m *Manager) Get(tag string) (adapter.Endpoint, bool) {
	m.access.Lock()
	defer m.access.Unlock()
	endpoint, found := m.endpointByTag[tag]
	return endpoint, found
}

func (m *Manager) Create(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, outboundType string, options any) error {
	endpoint, err := m.registry.Create(ctx, router, logger, tag, outboundType, options)
	if err != nil {
		return err
	}
	m.access.Lock()
	defer m.access.Unlock()
	_, loaded := m.endpointByTag[tag]
	if loaded {
		return E.New("duplicate endpoint tag: ", tag)
	}
	m.endpoints = append(m.endpoints, endpoint)
	m.endpointByTag[tag] = endpoint
	return nil
}

func (m *Manager) Replace(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, endpointType string, options any) error {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	node, err := m.registry.Create(ctx, router, logger, tag, endpointType, options)
	if err != nil {
		return err
	}
	if m.lifecycle != nil {
		for _, stage := range adapter.ListStartStages {
			// Providers start after the outbound manager has started endpoints, even
			// though the endpoint manager's own start stage runs later.
			last := m.stage
			if last < adapter.StartStateStart {
				last = adapter.StartStateStart
			}
			if stage > last {
				break
			}
			if err = m.lifecycle.Start("endpoint/"+node.Type()+"["+tag+"]", node, stage); err != nil {
				return E.Errors(err, m.lifecycle.Remove(node))
			}
		}
	}
	m.access.Lock()
	old := m.endpointByTag[tag]
	if old == nil {
		m.endpoints = append(m.endpoints, node)
	} else {
		for i, item := range m.endpoints {
			if item == old {
				m.endpoints[i] = node
				break
			}
		}
	}
	m.endpointByTag[tag] = node
	m.access.Unlock()
	if old != nil && m.lifecycle != nil {
		if closeErr := m.lifecycle.Remove(old); closeErr != nil {
			logger.Error(closeErr, "close replaced endpoint ", tag)
		}
	}
	return nil
}

func (m *Manager) Remove(tag string) error {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	m.access.Lock()
	old := m.endpointByTag[tag]
	if old == nil {
		m.access.Unlock()
		return nil
	}
	delete(m.endpointByTag, tag)
	for i, item := range m.endpoints {
		if item == old {
			m.endpoints = append(m.endpoints[:i], m.endpoints[i+1:]...)
			break
		}
	}
	m.access.Unlock()
	if m.lifecycle != nil {
		return m.lifecycle.Remove(old)
	}
	return nil
}
