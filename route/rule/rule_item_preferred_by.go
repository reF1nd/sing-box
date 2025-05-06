package rule

import (
	"context"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
	"github.com/sagernet/sing/service"
)

var _ RuleItem = (*PreferredByItem)(nil)

type PreferredByItem struct {
	ctx                 context.Context
	outboundTags        []string
	outbounds           []adapter.OutboundWithPreferredRoutes
	domainMatchStrategy C.DomainMatchStrategy
}

func NewPreferredByItem(ctx context.Context, outboundTags []string, domainMatchStrategy C.DomainMatchStrategy) *PreferredByItem {
	return &PreferredByItem{
		ctx:                 ctx,
		outboundTags:        outboundTags,
		domainMatchStrategy: domainMatchStrategy,
	}
}

func (r *PreferredByItem) Start() error {
	outboundManager := service.FromContext[adapter.OutboundManager](r.ctx)
	for _, outboundTag := range r.outboundTags {
		rawOutbound, loaded := outboundManager.Outbound(outboundTag)
		if !loaded {
			return E.New("outbound not found: ", outboundTag)
		}
		outboundWithPreferredRoutes, withRoutes := rawOutbound.(adapter.OutboundWithPreferredRoutes)
		if !withRoutes {
			return E.New("outbound type does not support preferred routes: ", rawOutbound.Type())
		}
		r.outbounds = append(r.outbounds, outboundWithPreferredRoutes)
	}
	return nil
}

func (r *PreferredByItem) Match(metadata *adapter.InboundContext) bool {
	var domainHost string
	switch r.domainMatchStrategy {
	case C.DomainMatchStrategyPreferFQDN:
		if metadata.Destination.IsFqdn() {
			domainHost = metadata.Destination.Fqdn
		} else if metadata.SniffHost != "" {
			domainHost = metadata.SniffHost
		} else {
			domainHost = metadata.Domain
		}
	case C.DomainMatchStrategyFQDNOnly:
		if metadata.Destination.IsFqdn() {
			domainHost = metadata.Destination.Fqdn
		}
	case C.DomainMatchStrategySniffHostOnly:
		if metadata.SniffHost != "" {
			domainHost = metadata.SniffHost
		}
	default:
		if metadata.SniffHost != "" {
			domainHost = metadata.SniffHost
		} else if metadata.Destination.IsFqdn() {
			domainHost = metadata.Destination.Fqdn
		} else {
			domainHost = metadata.Domain
		}
	}
	if domainHost != "" {
		for _, outbound := range r.outbounds {
			if outbound.PreferredDomain(domainHost) {
				return true
			}
		}
	}
	if metadata.Destination.IsIP() {
		for _, outbound := range r.outbounds {
			if outbound.PreferredAddress(metadata.Destination.Addr) {
				return true
			}
		}
	}
	if len(metadata.DestinationAddresses) > 0 {
		for _, address := range metadata.DestinationAddresses {
			for _, outbound := range r.outbounds {
				if outbound.PreferredAddress(address) {
					return true
				}
			}
		}
	}
	return false
}

func (r *PreferredByItem) String() string {
	description := "preferred_by="
	pLen := len(r.outboundTags)
	if pLen == 1 {
		description += F.ToString(r.outboundTags[0])
	} else {
		description += "[" + strings.Join(F.MapToString(r.outboundTags), " ") + "]"
	}
	return description
}
