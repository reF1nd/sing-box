package hosts

import (
	"context"
	"net/netip"
	"os"

	"github.com/sagernet/sing-box/adapter"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/dns"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
	"github.com/sagernet/sing/service/filemanager"

	mDNS "github.com/miekg/dns"
)

func RegisterTransport(registry *dns.TransportRegistry) {
	dns.RegisterTransport[option.HostsDNSServerOptions](registry, C.DNSTypeHosts, NewTransport)
}

var _ adapter.DNSTransport = (*Transport)(nil)

type Transport struct {
	dns.TransportAdapter
	ctx              context.Context
	files            []*File
	predefined       map[string][]netip.Addr
	predefinedDomain map[string]string
}

func NewTransport(ctx context.Context, logger log.ContextLogger, tag string, options option.HostsDNSServerOptions) (adapter.DNSTransport, error) {
	var (
		files            []*File
		predefined       = make(map[string][]netip.Addr)
		predefinedDomain = make(map[string]string)
	)
	if len(options.Path) == 0 {
		files = append(files, NewFile(DefaultPath))
	} else {
		for _, path := range options.Path {
			files = append(files, NewFile(filemanager.BasePath(ctx, os.ExpandEnv(path))))
		}
	}
	if options.Predefined != nil {
		for _, entry := range options.Predefined.Entries() {
			key := mDNS.CanonicalName(entry.Key)
			if entry.Value.Domain != "" {
				predefinedDomain[key] = mDNS.CanonicalName(entry.Value.Domain)
			} else {
				predefined[key] = entry.Value.Addresses
			}
		}
	}
	return &Transport{
		TransportAdapter: dns.NewTransportAdapter(C.DNSTypeHosts, tag, nil),
		ctx:              ctx,
		files:            files,
		predefined:       predefined,
		predefinedDomain: predefinedDomain,
	}, nil
}

func (t *Transport) Start(stage adapter.StartStage) error {
	return nil
}

func (t *Transport) Close() error {
	return nil
}

func (t *Transport) Reset() {
}

func (t *Transport) Exchange(ctx context.Context, message *mDNS.Msg) (*mDNS.Msg, error) {
	question := message.Question[0]
	domain := mDNS.CanonicalName(question.Name)
	if question.Qtype == mDNS.TypeA || question.Qtype == mDNS.TypeAAAA {
		if addresses, ok := t.predefined[domain]; ok {
			return dns.FixedResponse(message.Id, question, addresses, C.DefaultDNSTTL), nil
		}
		if targetDomain, ok := t.predefinedDomain[domain]; ok {
			dnsRouter := service.FromContext[adapter.DNSRouter](t.ctx)
			targetMsg := &mDNS.Msg{
				MsgHdr: mDNS.MsgHdr{
					RecursionDesired: true,
				},
				Question: []mDNS.Question{{
					Name:   targetDomain,
					Qtype:  question.Qtype,
					Qclass: mDNS.ClassINET,
				}},
			}
			resolveCtx, loopDetected := dns.ContextWithAliasResolution(adapter.OverrideContext(ctx), domain, targetDomain)
			if loopDetected {
				return &mDNS.Msg{
					MsgHdr: mDNS.MsgHdr{
						Id:       message.Id,
						Rcode:    mDNS.RcodeServerFailure,
						Response: true,
					},
					Question: []mDNS.Question{question},
				}, nil
			}
			response, err := dnsRouter.Exchange(resolveCtx, targetMsg, adapter.DNSQueryOptions{})
			if err != nil {
				return nil, err
			}
			if response.Rcode != mDNS.RcodeSuccess {
				return &mDNS.Msg{
					MsgHdr: mDNS.MsgHdr{
						Id:       message.Id,
						Rcode:    response.Rcode,
						Response: true,
					},
					Question: []mDNS.Question{question},
				}, nil
			}
			if len(response.Answer) == 0 {
				return &mDNS.Msg{
					MsgHdr: mDNS.MsgHdr{
						Id:       message.Id,
						Rcode:    mDNS.RcodeSuccess,
						Response: true,
					},
					Question: []mDNS.Question{question},
					Ns:       response.Ns,
					Extra:    response.Extra,
				}, nil
			}
			ttl := response.Answer[0].Header().Ttl
			var addresses []netip.Addr
			for _, rr := range response.Answer {
				if rr.Header().Ttl < ttl {
					ttl = rr.Header().Ttl
				}
				switch record := rr.(type) {
				case *mDNS.A:
					addresses = append(addresses, netip.AddrFrom4([4]byte(record.A.To4())))
				case *mDNS.AAAA:
					addresses = append(addresses, netip.AddrFrom16([16]byte(record.AAAA)))
				}
			}
			return dns.FixedResponse(message.Id, question, addresses, ttl), nil
		}
		for _, file := range t.files {
			addresses := file.Lookup(domain)
			if len(addresses) > 0 {
				return dns.FixedResponse(message.Id, question, addresses, C.DefaultDNSTTL), nil
			}
		}
	}
	return &mDNS.Msg{
		MsgHdr: mDNS.MsgHdr{
			Id:       message.Id,
			Rcode:    mDNS.RcodeNameError,
			Response: true,
		},
		Question: []mDNS.Question{question},
	}, nil
}
