package provider

import (
	"maps"
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
	a.outboundsAccess.RLock()
	activeOut := maps.Clone(a.outboundsByTag)
	activeEP := maps.Clone(a.endpointsByTag)
	a.outboundsAccess.RUnlock()
	outByTag, epByTag := make(map[string]adapter.Outbound), make(map[string]adapter.Outbound)
	var retainedOutTags, retainedEPTags []string
	var updateErr error
	for _, node := range ordered {
		ctx := adapter.WithContext(a.ctx, &adapter.InboundContext{Outbound: node.tag})
		ownedOut := activeOut[node.tag]
		ownedEP := activeEP[node.tag]
		if ownedOut == nil && ownedEP == nil {
			if _, exists := a.outbound.Outbound(node.tag); exists {
				updateErr = E.Errors(updateErr, E.New("provider node tag conflicts with existing outbound: ", node.tag))
				continue
			}
			if a.endpoint != nil {
				if _, exists := a.endpoint.Get(node.tag); exists {
					updateErr = E.Errors(updateErr, E.New("provider node tag conflicts with existing endpoint: ", node.tag))
					continue
				}
			}
		}
		if node.outbound != nil {
			if ownedOut != nil && reflect.DeepEqual(*node.outbound, a.appliedOutbounds[node.tag]) {
				outByTag[node.tag] = ownedOut
				continue
			}
			err := a.outbound.Replace(ctx, a.router, a.logFactory.NewLogger("outbound/"+node.kind+"["+node.tag+"]"), node.tag, node.kind, node.options)
			if err != nil {
				updateErr = E.Errors(updateErr, E.Cause(err, node.tag))
				if ownedOut != nil {
					outByTag[node.tag] = ownedOut
				} else if ownedEP != nil {
					epByTag[node.tag] = ownedEP
					retainedEPTags = append(retainedEPTags, node.tag)
				}
				continue
			}
			if ownedEP != nil {
				if removeErr := a.endpoint.Remove(node.tag); removeErr != nil {
					a.logger.Error(removeErr, "close endpoint [", node.tag, "]")
				}
			}
			current, _ := a.outbound.Outbound(node.tag)
			a.appliedOutbounds[node.tag] = *node.outbound
			outByTag[node.tag] = current
		} else {
			if ownedEP != nil && reflect.DeepEqual(*node.endpoint, a.appliedEndpoints[node.tag]) {
				epByTag[node.tag] = ownedEP
				continue
			}
			err := a.endpoint.Replace(ctx, a.router, a.logFactory.NewLogger("endpoint/"+node.kind+"["+node.tag+"]"), node.tag, node.kind, node.options)
			if err != nil {
				updateErr = E.Errors(updateErr, E.Cause(err, node.tag))
				if ownedEP != nil {
					epByTag[node.tag] = ownedEP
				} else if ownedOut != nil {
					outByTag[node.tag] = ownedOut
					retainedOutTags = append(retainedOutTags, node.tag)
				}
				continue
			}
			if ownedOut != nil {
				if removeErr := a.outbound.Remove(node.tag); removeErr != nil {
					a.logger.Error(removeErr, "close outbound [", node.tag, "]")
				}
			}
			current, _ := a.endpoint.Get(node.tag)
			a.appliedEndpoints[node.tag] = *node.endpoint
			epByTag[node.tag] = current
		}
	}
	keepOutTags := make([]string, 0, len(outByTag))
	for tag := range outByTag {
		keepOutTags = append(keepOutTags, tag)
	}
	keepEPTags := make([]string, 0, len(epByTag))
	for tag := range epByTag {
		keepEPTags = append(keepEPTags, tag)
	}
	a.removeUseless(keepOutTags)
	a.removeUselessEndpoints(keepEPTags)
	var outbounds, endpoints []adapter.Outbound
	for _, tag := range outTags {
		if node := outByTag[tag]; node != nil {
			outbounds = append(outbounds, node)
		}
	}
	for _, tag := range retainedOutTags {
		if node := outByTag[tag]; node != nil {
			outbounds = append(outbounds, node)
		}
	}
	for _, tag := range epTags {
		if node := epByTag[tag]; node != nil {
			endpoints = append(endpoints, node)
		}
	}
	for _, tag := range retainedEPTags {
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
