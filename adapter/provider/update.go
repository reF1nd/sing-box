package provider

import (
	"reflect"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
)

type updateNode struct {
	tag      string
	kind     string
	options  any
	outbound *option.Outbound
	endpoint *option.Endpoint
}

// UpdateNodes orders outbounds and endpoints together, so a subscription can
// introduce a detour and its users in either order without restarting them.
func (a *Adapter) UpdateNodes(outOpts []option.Outbound, epOpts []option.Endpoint) error {
	outTags, epTags := a.resolveOutboundTags(outOpts), a.resolveEndpointTags(epOpts)
	nodes := make(map[string]updateNode, len(outOpts)+len(epOpts))
	tags := append(append([]string(nil), outTags...), epTags...)
	for i := range outOpts {
		opt := &outOpts[i]
		nodes[outTags[i]] = updateNode{outTags[i], opt.Type, opt.Options, opt, nil}
	}
	for i := range epOpts {
		opt := &epOpts[i]
		if _, found := nodes[epTags[i]]; found {
			return E.New("duplicate provider node tag: ", epTags[i])
		}
		nodes[epTags[i]] = updateNode{epTags[i], opt.Type, opt.Options, nil, opt}
	}
	var ordered []updateNode
	visiting, visited := make(map[string]bool), make(map[string]bool)
	var visit func(string) error
	visit = func(tag string) error {
		if visited[tag] {
			return nil
		}
		if visiting[tag] {
			return E.New("circular provider dependency: ", tag)
		}
		visiting[tag] = true
		node := nodes[tag]
		var dependencies []string
		if opts, ok := node.options.(option.DialerOptionsWrapper); ok {
			if detour := opts.TakeDialerOptions().Detour; detour != "" {
				dependencies = append(dependencies, detour)
			}
		}
		switch opts := node.options.(type) {
		case *option.SelectorOutboundOptions:
			dependencies = append(dependencies, opts.Outbounds...)
		case *option.URLTestOutboundOptions:
			dependencies = append(dependencies, opts.Outbounds...)
		}
		for _, dep := range dependencies {
			if _, internal := nodes[dep]; internal {
				if err := visit(dep); err != nil {
					return err
				}
			} else {
				if _, found := a.outbound.Outbound(dep); !found {
					return E.New("provider dependency not found: ", dep)
				}
				// An old subscription node scheduled for removal is not a usable dependency.
				if _, owned := a.appliedOutbounds[dep]; owned {
					return E.New("provider dependency removed: ", dep)
				}
				if _, owned := a.appliedEndpoints[dep]; owned {
					return E.New("provider dependency removed: ", dep)
				}
			}
		}
		visiting[tag] = false
		visited[tag] = true
		ordered = append(ordered, node)
		return nil
	}
	for _, tag := range tags {
		if err := visit(tag); err != nil {
			return err
		}
	}
	activeOut, activeEP := a.activeOutboundTags(), a.activeEndpointTags()
	outByTag, epByTag := make(map[string]adapter.Outbound), make(map[string]adapter.Outbound)
	var updateErr error
	for _, node := range ordered {
		ctx := adapter.WithContext(a.ctx, &adapter.InboundContext{Outbound: node.tag})
		if node.outbound != nil {
			current, exists := a.outbound.Outbound(node.tag)
			if !exists || !activeOut[node.tag] || !reflect.DeepEqual(*node.outbound, a.appliedOutbounds[node.tag]) {
				err := a.outbound.Replace(ctx, a.router, a.logFactory.NewLogger("outbound/"+node.kind+"["+node.tag+"]"), node.tag, node.kind, node.options)
				if err != nil {
					updateErr = E.Errors(updateErr, E.Cause(err, node.tag))
					if activeOut[node.tag] {
						outByTag[node.tag] = current
					}
					continue
				}
				current, _ = a.outbound.Outbound(node.tag)
				a.appliedOutbounds[node.tag] = *node.outbound
			}
			outByTag[node.tag] = current
		} else {
			current, exists := a.endpoint.Get(node.tag)
			if !exists || !activeEP[node.tag] || !reflect.DeepEqual(*node.endpoint, a.appliedEndpoints[node.tag]) {
				err := a.endpoint.Replace(ctx, a.router, a.logFactory.NewLogger("endpoint/"+node.kind+"["+node.tag+"]"), node.tag, node.kind, node.options)
				if err != nil {
					updateErr = E.Errors(updateErr, E.Cause(err, node.tag))
					if activeEP[node.tag] {
						epByTag[node.tag] = current
					}
					continue
				}
				current, _ = a.endpoint.Get(node.tag)
				a.appliedEndpoints[node.tag] = *node.endpoint
			}
			epByTag[node.tag] = current
		}
	}
	a.removeUseless(outTags)
	a.removeUselessEndpoints(epTags)
	var outbounds, endpoints []adapter.Outbound
	for _, tag := range outTags {
		if node := outByTag[tag]; node != nil {
			outbounds = append(outbounds, node)
		}
	}
	for _, tag := range epTags {
		if node := epByTag[tag]; node != nil {
			endpoints = append(endpoints, node)
		}
	}
	a.outboundsAccess.Lock()
	a.outbounds, a.outboundsByTag = outbounds, outByTag
	a.endpoints, a.endpointsByTag = endpoints, epByTag
	a.outboundsAccess.Unlock()
	for tag := range a.appliedOutbounds {
		if _, found := outByTag[tag]; !found {
			delete(a.appliedOutbounds, tag)
		}
	}
	for tag := range a.appliedEndpoints {
		if _, found := epByTag[tag]; !found {
			delete(a.appliedEndpoints, tag)
		}
	}
	if a.enabled && a.history != nil {
		a.run(func() { a.HealthCheck(a.ctx) })
	}
	return updateErr
}
