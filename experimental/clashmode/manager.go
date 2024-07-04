package clashmode

import (
	"context"
	"strings"
	"sync"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/observable"
	"github.com/sagernet/sing/service"
)

type Manager struct {
	ctx           context.Context
	logger        log.Logger
	dnsRouter     adapter.DNSRouter
	setModeAccess sync.Mutex
	modeAccess    sync.RWMutex
	mode          string
	modeList      []string
	updateAccess  sync.Mutex
	updateHooks   []*observable.Subscriber[struct{}]
}

func NewManager(ctx context.Context, logger log.Logger, defaultMode string, modeList []string) *Manager {
	if defaultMode == "" {
		defaultMode = "Rule"
	}
	if !common.Contains(modeList, defaultMode) {
		modeList = append([]string{defaultMode}, modeList...)
	}
	return &Manager{
		ctx:       ctx,
		logger:    logger,
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
		mode:      defaultMode,
		modeList:  modeList,
	}
}

func (m *Manager) Name() string {
	return "clash mode manager"
}

func (m *Manager) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	m.setModeAccess.Lock()
	defer m.setModeAccess.Unlock()
	cacheFile := service.FromContext[adapter.CacheFile](m.ctx)
	if cacheFile != nil {
		mode := cacheFile.LoadMode()
		if common.Any(m.modeList, func(it string) bool {
			return strings.EqualFold(it, mode)
		}) {
			m.modeAccess.Lock()
			m.mode = mode
			m.modeAccess.Unlock()
		}
	}
	return nil
}

func (m *Manager) Mode() string {
	m.modeAccess.RLock()
	defer m.modeAccess.RUnlock()
	return m.mode
}

func (m *Manager) ModeList() []string {
	return m.modeList
}

func (m *Manager) AddUpdateHook(hook *observable.Subscriber[struct{}]) {
	m.updateAccess.Lock()
	defer m.updateAccess.Unlock()
	m.updateHooks = append(m.updateHooks, hook)
}

func (m *Manager) SetMode(newMode string) {
	if !common.Contains(m.modeList, newMode) {
		newMode = common.Find(m.modeList, func(it string) bool {
			return strings.EqualFold(it, newMode)
		})
	}
	if !common.Contains(m.modeList, newMode) {
		return
	}
	m.setModeAccess.Lock()
	defer m.setModeAccess.Unlock()
	m.modeAccess.Lock()
	if newMode == m.mode {
		m.modeAccess.Unlock()
		return
	}
	m.mode = newMode
	m.modeAccess.Unlock()
	m.updateAccess.Lock()
	for _, hook := range m.updateHooks {
		hook.Emit(struct{}{})
	}
	m.updateAccess.Unlock()
	if m.dnsRouter != nil {
		m.dnsRouter.ClearCache()
	}
	cacheFile := service.FromContext[adapter.CacheFile](m.ctx)
	if cacheFile != nil {
		err := cacheFile.StoreMode(newMode)
		if err != nil {
			m.logger.Error(E.Cause(err, "save mode"))
		}
	}
	m.logger.Info("updated mode: ", newMode)
}

var _ adapter.LifecycleService = (*Manager)(nil)
