package adapter

import (
	"context"
	"time"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/x/list"
)

// Provider is the interface of proxy provider
type Provider interface {
	Type() string
	Tag() string
	Outbounds() []Outbound
	Outbound(tag string) (Outbound, bool)
	RegisterCallback(callback ProviderUpdateCallback) *list.Element[ProviderUpdateCallback]
	UnregisterCallback(element *list.Element[ProviderUpdateCallback])
}

type ProviderRemote interface {
	Update() error
	UpdatedAt() time.Time
}

// ProviderInfoer is the interface of provider with info
type ProviderInfoer interface {
	Provider
	Info() *ProviderRemoteInfo
}

// ProviderRegistry is the interface of provider registry
type ProviderRegistry interface {
	option.ProviderOptionsRegistry
	CreateProvider(ctx context.Context, router Router, logFactory log.Factory, tag string, providerType string, options any) (Provider, error)
}

// ProviderManager is the interface of provider manager
type ProviderManager interface {
	Lifecycle
	Providers() []Provider
	Provider(tag string) (Provider, bool)
	Remove(tag string) error
	Create(ctx context.Context, router Router, logFactory log.Factory, tag string, providerType string, options any) error
}

// ProviderInfo is the info of provider
type ProviderRemoteInfo struct {
	Upload      int64
	Download    int64
	Total       int64
	Expire      int64
	LastUpdated time.Time
}

type ProviderUpdateCallback = func(name string, outbounds []Outbound)
