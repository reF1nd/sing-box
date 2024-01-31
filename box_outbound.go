package box

import (
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/datastructure"
	"github.com/sagernet/sing-box/common/taskmonitor"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
)

func (s *Box) startOutboundsAndOutboundProviders() error {
	outboundGraph := datastructure.NewGraph[string, adapter.Outbound]()
	startedOutboundMap := make(map[string]bool)
	startedProviderMap := make(map[string]bool)
	for _, out := range s.outbounds {
		node := outboundGraph.GetNode(out.Tag())
		if node == nil {
			node = datastructure.NewGraphNode[string, adapter.Outbound](out.Tag(), out)
			outboundGraph.AddNode(node)
		} else {
			data := node.Data()
			if data != nil {
				return E.New("outbound [", out.Tag(), "] already exists")
			}
			node.SetData(out)
		}
		for _, dependency := range out.Dependencies() {
			dpNode := outboundGraph.GetNode(dependency)
			if dpNode == nil {
				dpNode = datastructure.NewGraphNode[string, adapter.Outbound](dependency, nil)
				outboundGraph.AddNode(dpNode)
			}
			dpNode.AddNext(node)
			node.AddPrev(dpNode)
		}
	}
	for _, provider := range s.outboundProviders {
		_, loaded := startedProviderMap[provider.Tag()]
		if loaded {
			return E.New("outbound-provider [", provider.Tag(), "] already exists")
		}
		startedProviderMap[provider.Tag()] = false
		dependentOutbound := provider.DependentOutbound()
		if dependentOutbound != "" {
			outNode := outboundGraph.GetNode(dependentOutbound)
			if outNode == nil {
				outNode = datastructure.NewGraphNode[string, adapter.Outbound](dependentOutbound, nil)
				outboundGraph.AddNode(outNode)
			}
		}
	}
	outboundQueue := datastructure.NewQueue[*datastructure.GraphNode[string, adapter.Outbound]]()
	providerQueue := datastructure.NewQueue[adapter.OutboundProvider]()
	monitor := taskmonitor.New(s.logger, C.DefaultStartTimeout)
	for {
		for outboundQueue.Len() > 0 {
			node := outboundQueue.Pop()
			out := node.Data()
			starter, isStarter := out.(common.Starter)
			if isStarter {
				monitor.Start("initialize outbound/", out.Type(), "[", out.Tag(), "]")
				err := starter.Start()
				monitor.Finish()
				if err != nil {
					return E.Cause(err, "initialize outbound/", out.Type(), "[", out.Tag(), "]")
				}
			}
			startedOutboundMap[out.Tag()] = true
			for _, next := range node.Next() {
				next.RemovePrev(node)
			}
		}
		for providerQueue.Len() > 0 {
			provider := providerQueue.Pop()
			monitor.Start("pre-start outbound-provider[", provider.Tag(), "]")
			err := provider.PreStart()
			monitor.Finish()
			if err != nil {
				return E.Cause(err, "pre-start outbound-provider[", provider.Tag(), "]")
			}
			outbounds := provider.Outbounds()
			for _, outbound := range outbounds {
				outNode := outboundGraph.GetNode(outbound.Tag())
				if outNode == nil {
					outNode = datastructure.NewGraphNode[string, adapter.Outbound](outbound.Tag(), outbound)
					outboundGraph.AddNode(outNode)
				} else {
					data := outNode.Data()
					if data != nil {
						return E.New("outbound [", outbound.Tag(), "] already exists")
					}
					outNode.SetData(outbound)
				}
				for _, dependency := range outbound.Dependencies() {
					dpNode := outboundGraph.GetNode(dependency)
					if dpNode == nil {
						dpNode = datastructure.NewGraphNode[string, adapter.Outbound](dependency, nil)
						outboundGraph.AddNode(dpNode)
					}
					if !startedOutboundMap[dependency] {
						dpNode.AddNext(outNode)
						outNode.AddPrev(dpNode)
					}
				}
			}
			startedProviderMap[provider.Tag()] = true
		}
		for _, node := range outboundGraph.NodeMap() {
			if len(node.Prev()) == 0 && node.Data() != nil {
				if !startedOutboundMap[node.ID()] {
					outboundQueue.Push(node)
				}
			}
		}
		for _, provider := range s.outboundProviders {
			if startedProviderMap[provider.Tag()] {
				continue
			}
			dpOut := provider.DependentOutbound()
			if dpOut == "" {
				providerQueue.Push(provider)
			} else {
				if startedOutboundMap[dpOut] {
					providerQueue.Push(provider)
				}
			}
		}
		if outboundQueue.Len() == 0 && providerQueue.Len() == 0 {
			break
		}
	}
	if len(startedOutboundMap) != len(outboundGraph.NodeMap()) {
		circles := outboundGraph.FindCircle()
		if len(circles) > 0 {
			firstCircle := circles[0]
			for i := range firstCircle {
				firstCircle[i] = "outbound[" + firstCircle[i] + "]"
			}
			s := strings.Join(firstCircle, " -> ")
			s += " -> outbound[" + firstCircle[0] + "]"
			return E.New("outbound circle found: ", s)
		}
		for _, node := range outboundGraph.NodeMap() {
			if node.Data() == nil {
				for _, provider := range s.outboundProviders {
					if node.ID() == provider.Tag() {
						return E.New("outbound [", provider.DependentOutbound(), "] not found")
					}
				}
				return E.New("outbound [", node.ID(), "] not found")
			}
		}
	}
	return nil
}
