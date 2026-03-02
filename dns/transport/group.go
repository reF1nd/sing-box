package transport

import (
	"context"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/service"

	mDNS "github.com/miekg/dns"
)

var _ adapter.DNSTransport = (*GroupTransport)(nil)

func RegisterGroup(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.GroupDNSServerOptions](registry, C.DNSTypeGroup, NewGroup)
}

type GroupTransport struct {
	dns.TransportAdapter

	ctx        context.Context
	logger     log.ContextLogger
	serverTags []string
}

func NewGroup(ctx context.Context, logger log.ContextLogger, tag string, options option.GroupDNSServerOptions) (adapter.DNSTransport, error) {
	if len(options.Servers) == 0 {
		return nil, E.New("missing servers")
	}
	return &GroupTransport{
		TransportAdapter: dns.NewTransportAdapter(C.DNSTypeGroup, tag, options.Servers),
		ctx:              ctx,
		logger:           logger,
		serverTags:       options.Servers,
	}, nil
}

func (t *GroupTransport) Start(stage adapter.StartStage) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	transportManager := service.FromContext[adapter.DNSTransportManager](t.ctx)
	if transportManager == nil {
		return E.New("missing DNS transport manager")
	}
	for _, tag := range t.serverTags {
		transport, loaded := transportManager.Transport(tag)
		if !loaded {
			return E.New("DNS server not found: ", tag)
		}
		if transport.Type() == C.DNSTypeGroup {
			return E.New("group cannot contain another group: ", tag)
		}
		if transport.Type() == C.DNSTypeFakeIP {
			return E.New("group cannot contain fakeip server: ", tag)
		}
	}
	return nil
}

func (t *GroupTransport) Close() error {
	return nil
}

func (t *GroupTransport) Reset() {
}

func (t *GroupTransport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	transportManager := service.FromContext[adapter.DNSTransportManager](t.ctx)
	if transportManager == nil {
		return nil, E.New("missing DNS transport manager")
	}

	type result struct {
		response *mDNS.Msg
		tag      string
		err      error
	}

	resultCh := make(chan result, len(t.serverTags))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for _, tag := range t.serverTags {
		transport, loaded := transportManager.Transport(tag)
		if !loaded {
			resultCh <- result{nil, tag, E.New("DNS server not found: ", tag)}
			continue
		}
		go func(transport adapter.DNSTransport, tag string) {
			resp, err := transport.Exchange(ctx, message.Copy())
			resultCh <- result{resp, tag, err}
		}(transport, tag)
	}

	var firstErr error
	for range t.serverTags {
		r := <-resultCh
		if r.err == nil && r.response != nil {
			t.logger.DebugContext(ctx, "fastest response from ", r.tag)
			return r.response, nil
		}
		if firstErr == nil && r.err != nil {
			firstErr = r.err
		}
	}

	if firstErr != nil {
		return nil, firstErr
	}
	return nil, E.New("all DNS servers failed")
}
