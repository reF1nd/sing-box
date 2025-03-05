package group

import (
	"context"
	"net"
	"regexp"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/interrupt"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/atomic"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

func RegisterSelector(registry *outbound.Registry) {
	outbound.Register[option.SelectorOutboundOptions](registry, C.TypeSelector, NewSelector)
}

var (
	_ adapter.OutboundGroup             = (*Selector)(nil)
	_ adapter.ConnectionHandlerEx       = (*Selector)(nil)
	_ adapter.PacketConnectionHandlerEx = (*Selector)(nil)
)

type Selector struct {
	outbound.Adapter
	ctx                          context.Context
	outbound                     adapter.OutboundManager
	provider                     adapter.ProviderManager
	connection                   adapter.ConnectionManager
	logger                       logger.ContextLogger
	tags                         []string
	defaultTag                   string
	outbounds                    map[string]adapter.Outbound
	selected                     atomic.TypedValue[adapter.Outbound]
	interruptGroup               *interrupt.Group
	interruptExternalConnections bool

	include           *regexp.Regexp
	exclude           *regexp.Regexp
	providerTags      []string
	use_all_providers bool
}

func NewSelector(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.SelectorOutboundOptions) (adapter.Outbound, error) {
	if len(options.Outbounds)+len(options.Providers) == 0 && !options.UseAllProviders {
		return nil, E.New("missing outbound and provider tags")
	}
	var (
		err              error
		exclude, include *regexp.Regexp
	)
	if options.Exclude != "" {
		exclude, err = regexp.Compile(options.Exclude)
		if err != nil {
			return nil, err
		}
	}
	if options.Include != "" {
		include, err = regexp.Compile(options.Include)
		if err != nil {
			return nil, err
		}
	}
	outbound := &Selector{
		Adapter:                      outbound.NewAdapter(C.TypeSelector, tag, []string{N.NetworkTCP, N.NetworkUDP}, options.Outbounds),
		ctx:                          ctx,
		outbound:                     service.FromContext[adapter.OutboundManager](ctx),
		provider:                     service.FromContext[adapter.ProviderManager](ctx),
		connection:                   service.FromContext[adapter.ConnectionManager](ctx),
		logger:                       logger,
		tags:                         options.Outbounds,
		defaultTag:                   options.Default,
		outbounds:                    make(map[string]adapter.Outbound),
		interruptGroup:               interrupt.NewGroup(),
		interruptExternalConnections: options.InterruptExistConnections,
		include:                      include,
		exclude:                      exclude,
		providerTags:                 options.Providers,
		use_all_providers:            options.UseAllProviders,
	}
	return outbound, nil
}

func (s *Selector) Network() []string {
	selected := s.selected.Load()
	if selected == nil {
		return []string{N.NetworkTCP, N.NetworkUDP}
	}
	return selected.Network()
}

func (s *Selector) Start() error {
	outbounds := make([]adapter.Outbound, 0, len(s.tags))
	for i, tag := range s.tags {
		detour, loaded := s.outbound.Outbound(tag)
		if !loaded {
			return E.New("outbound ", i, " not found: ", tag)
		}
		s.outbounds[tag] = detour
		outbounds = append(outbounds, detour)
	}
	err := s.ensureSelected()
	if err != nil {
		return err
	}
	if s.use_all_providers {
		providerTags := make([]string, 0)
		for _, p := range s.provider.Providers() {
			providerTags = append(providerTags, p.Tag())
		}
		s.providerTags = providerTags
	}
	onProviderChange := s.createCallback(outbounds)
	for _, tag := range s.providerTags {
		provider, ok := s.provider.Provider(tag)
		if !ok {
			return E.New("provider not found: ", tag)
		}
		provider.RegisterCallback(onProviderChange)
	}
	return nil
}

func (s *Selector) Now() string {
	selected := s.selected.Load()
	if selected == nil {
		return s.tags[0]
	}
	return selected.Tag()
}

func (s *Selector) All() []string {
	return s.tags
}

func (s *Selector) SelectOutbound(tag string) bool {
	detour, loaded := s.outbounds[tag]
	if !loaded {
		return false
	}
	if s.selected.Swap(detour) == detour {
		return true
	}
	if s.Tag() != "" {
		cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
		if cacheFile != nil {
			err := cacheFile.StoreSelected(s.Tag(), tag)
			if err != nil {
				s.logger.Error("store selected: ", err)
			}
		}
	}
	s.interruptGroup.Interrupt(s.interruptExternalConnections)
	return true
}

func (s *Selector) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	conn, err := s.selected.Load().DialContext(ctx, network, destination)
	if err != nil {
		return nil, err
	}
	return s.interruptGroup.NewConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

func (s *Selector) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	conn, err := s.selected.Load().ListenPacket(ctx, destination)
	if err != nil {
		return nil, err
	}
	return s.interruptGroup.NewPacketConn(conn, interrupt.IsExternalConnectionFromContext(ctx)), nil
}

func (s *Selector) NewConnectionEx(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	selected := s.selected.Load()
	if outboundHandler, isHandler := selected.(adapter.ConnectionHandlerEx); isHandler {
		outboundHandler.NewConnectionEx(ctx, conn, metadata, onClose)
	} else {
		s.connection.NewConnection(ctx, selected, conn, metadata, onClose)
	}
}

func (s *Selector) NewPacketConnectionEx(ctx context.Context, conn N.PacketConn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	ctx = interrupt.ContextWithIsExternalConnection(ctx)
	selected := s.selected.Load()
	if outboundHandler, isHandler := selected.(adapter.PacketConnectionHandlerEx); isHandler {
		outboundHandler.NewPacketConnectionEx(ctx, conn, metadata, onClose)
	} else {
		s.connection.NewPacketConnection(ctx, selected, conn, metadata, onClose)
	}
}

func RealTag(detour adapter.Outbound) string {
	if group, isGroup := detour.(adapter.OutboundGroup); isGroup {
		return group.Now()
	}
	return detour.Tag()
}

func (s *Selector) createCallback(outbounds []adapter.Outbound) adapter.ProviderUpdateCallback {
	cache := make(map[string][]adapter.Outbound)
	uses := append([]string{""}, s.providerTags...)
	cache[uses[0]] = outbounds

	return func(name string, outbounds []adapter.Outbound) {
		tags := make([]string, 0, len(s.tags))
		outsByTag := make(map[string]adapter.Outbound)
		for _, tag := range uses {
			if name != tag {
				for _, out := range cache[tag] {
					tags = append(tags, out.Tag())
					outsByTag[out.Tag()] = out
				}
				continue
			}

			cache[name] = make([]adapter.Outbound, 0, len(outbounds))
			for _, out := range outbounds {
				if s.include != nil && !s.include.MatchString(out.Tag()) {
					continue
				}
				if s.exclude != nil && s.exclude.MatchString(out.Tag()) {
					continue
				}
				cache[name] = append(cache[name], out)
				tags = append(tags, out.Tag())
				outsByTag[out.Tag()] = out
			}
		}

		s.tags = tags
		s.outbounds = outsByTag
		s.ensureSelected()
	}
}

func (s *Selector) ensureSelected() error {
	if len(s.tags) == 0 {
		detour, _ := s.outbound.Outbound("OUTBOUNDLESS")
		s.tags = append(s.tags, detour.Tag())
		s.outbounds[detour.Tag()] = detour
		s.selected.Store(detour)
		return nil
	}

	if s.Tag() != "" {
		cacheFile := service.FromContext[adapter.CacheFile](s.ctx)
		if cacheFile != nil {
			selected := cacheFile.LoadSelected(s.Tag())
			if selected != "" {
				detour := s.selected.Load()
				if detour != nil && detour.Tag() == selected {
					return nil
				}
				detour, loaded := s.outbounds[selected]
				if loaded {
					s.selected.Store(detour)
					return nil
				}
			}
		}
	}

	if s.defaultTag != "" {
		detour, loaded := s.outbounds[s.defaultTag]
		if !loaded {
			return E.New("default outbound not found: ", s.defaultTag)
		}
		s.selected.Store(detour)
		return nil
	}

	s.selected.Store(s.outbounds[s.tags[0]])
	return nil
}
