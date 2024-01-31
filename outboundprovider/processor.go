package outboundprovider

import "github.com/sagernet/sing-box/option"

type processor struct {
	outbounds          []option.Outbound
	outboundByTag      map[string]*option.Outbound
	groupOutbounds     []option.Outbound
	groupOutboundByTag map[string]*option.Outbound
}

func newProcessor(outbounds []option.Outbound) *processor {
	p := &processor{
		outbounds: outbounds,
	}
	p.outboundByTag = make(map[string]*option.Outbound, len(outbounds))
	for i := range outbounds {
		outbound := &outbounds[i]
		p.outboundByTag[outbound.Tag] = outbound
	}
	return p
}

func (p *processor) initGroup() {
	if p.groupOutboundByTag == nil {
		p.groupOutboundByTag = make(map[string]*option.Outbound)
	}
}

func (p *processor) BasicOutbounds() []option.Outbound {
	return p.outbounds
}

func (p *processor) GroupOutbounds() []option.Outbound {
	return p.groupOutbounds
}

func (p *processor) AddOutbound(outbound option.Outbound) {
	p.outbounds = append(p.outbounds, outbound)
	p.outboundByTag[outbound.Tag] = &outbound
}

func (p *processor) GetOutbound(tag string) *option.Outbound {
	return p.outboundByTag[tag]
}

func (p *processor) DeleteOutbound(tag string) {
	outbound := p.outboundByTag[tag]
	if outbound == nil {
		return
	}
	delete(p.outboundByTag, tag)
	for i := range p.outbounds {
		if &p.outbounds[i] == outbound {
			if i == 0 {
				p.outbounds = p.outbounds[1:]
			} else {
				p.outbounds = append(p.outbounds[:i], p.outbounds[i+1:]...)
			}
			break
		}
	}
}

func (p *processor) ForeachOutbounds(f func(outbound *option.Outbound) bool) bool {
	for i := range p.outbounds {
		if !f(&p.outbounds[i]) {
			return false
		}
	}
	return true
}

func (p *processor) AddGroupOutbound(outbound option.Outbound) {
	p.initGroup()
	p.groupOutbounds = append(p.groupOutbounds, outbound)
	p.groupOutboundByTag[outbound.Tag] = &outbound
}

func (p *processor) GetGroupOutbound(tag string) *option.Outbound {
	if p.groupOutboundByTag == nil {
		return nil
	}
	return p.groupOutboundByTag[tag]
}

func (p *processor) DeleteGroupOutbound(tag string) {
	if p.groupOutboundByTag == nil {
		return
	}
	outbound := p.groupOutboundByTag[tag]
	if outbound == nil {
		return
	}
	delete(p.groupOutboundByTag, tag)
	for i := range p.groupOutbounds {
		if &p.groupOutbounds[i] == outbound {
			if i == 0 {
				p.groupOutbounds = p.groupOutbounds[1:]
			} else {
				p.groupOutbounds = append(p.groupOutbounds[:i], p.groupOutbounds[i+1:]...)
			}
			break
		}
	}
}

func (p *processor) ForeachGroupOutbounds(f func(outbound *option.Outbound) bool) bool {
	for i := range p.groupOutbounds {
		if !f(&p.groupOutbounds[i]) {
			return false
		}
	}
	return true
}
