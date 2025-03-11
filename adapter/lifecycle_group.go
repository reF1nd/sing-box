package adapter

import (
	"os"
	"slices"
	"sync"

	E "github.com/sagernet/sing/common/exceptions"
)

// LifecycleGroup owns components that can be replaced while their parent is
// running. Each component has a separate scope; removed scopes are released
// immediately instead of accumulating in the parent's cleanup list.
type LifecycleGroup struct {
	closed bool
	access sync.Mutex
	parent *Scope
	scopes map[Lifecycle]*Scope
	order  []Lifecycle
}

func NewLifecycleGroup(parent *Scope) *LifecycleGroup {
	g := &LifecycleGroup{parent: parent, scopes: make(map[Lifecycle]*Scope)}
	parent.Add(g.Close)
	return g
}

func (g *LifecycleGroup) Start(name string, component Lifecycle, stage StartStage) error {
	g.access.Lock()
	defer g.access.Unlock()
	if g.closed {
		return os.ErrClosed
	}
	if err := g.parent.Context().Err(); err != nil {
		return err
	}
	scope := g.scopes[component]
	if scope == nil {
		scope = NewScope(g.parent.Context(), g.parent.logger)
		g.scopes[component] = scope
		g.order = append(g.order, component)
	}
	return scope.Start(name, component, stage)
}

func (g *LifecycleGroup) Remove(component Lifecycle) error {
	g.access.Lock()
	defer g.access.Unlock()
	scope := g.scopes[component]
	if scope == nil {
		return nil
	}
	delete(g.scopes, component)
	for i, item := range g.order {
		if item == component {
			g.order = slices.Delete(g.order, i, i+1)
			break
		}
	}
	return scope.Close()
}

func (g *LifecycleGroup) Close() error {
	g.access.Lock()
	defer g.access.Unlock()
	g.closed = true
	var err error
	for i := len(g.order) - 1; i >= 0; i-- {
		err = E.Errors(err, g.scopes[g.order[i]].Close())
	}
	g.scopes = nil
	g.order = nil
	return err
}
