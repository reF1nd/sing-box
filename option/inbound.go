package option

import (
	"time"

	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

type _Inbound struct {
	Type               string                    `json:"type"`
	Tag                string                    `json:"tag,omitempty"`
	TunOptions         TunInboundOptions         `json:"-"`
	RedirectOptions    RedirectInboundOptions    `json:"-"`
	TProxyOptions      TProxyInboundOptions      `json:"-"`
	DirectOptions      DirectInboundOptions      `json:"-"`
	SocksOptions       SocksInboundOptions       `json:"-"`
	HTTPOptions        HTTPMixedInboundOptions   `json:"-"`
	MixedOptions       HTTPMixedInboundOptions   `json:"-"`
	ShadowsocksOptions ShadowsocksInboundOptions `json:"-"`
	VMessOptions       VMessInboundOptions       `json:"-"`
	TrojanOptions      TrojanInboundOptions      `json:"-"`
	NaiveOptions       NaiveInboundOptions       `json:"-"`
	HysteriaOptions    HysteriaInboundOptions    `json:"-"`
	ShadowTLSOptions   ShadowTLSInboundOptions   `json:"-"`
	VLESSOptions       VLESSInboundOptions       `json:"-"`
	TUICOptions        TUICInboundOptions        `json:"-"`
	Hysteria2Options   Hysteria2InboundOptions   `json:"-"`
}

type Inbound _Inbound

func (h *Inbound) RawOptions() (any, error) {
	var rawOptionsPtr any
	switch h.Type {
	case C.TypeTun:
		rawOptionsPtr = &h.TunOptions
	case C.TypeRedirect:
		rawOptionsPtr = &h.RedirectOptions
	case C.TypeTProxy:
		rawOptionsPtr = &h.TProxyOptions
	case C.TypeDirect:
		rawOptionsPtr = &h.DirectOptions
	case C.TypeSOCKS:
		rawOptionsPtr = &h.SocksOptions
	case C.TypeHTTP:
		rawOptionsPtr = &h.HTTPOptions
	case C.TypeMixed:
		rawOptionsPtr = &h.MixedOptions
	case C.TypeShadowsocks:
		rawOptionsPtr = &h.ShadowsocksOptions
	case C.TypeVMess:
		rawOptionsPtr = &h.VMessOptions
	case C.TypeTrojan:
		rawOptionsPtr = &h.TrojanOptions
	case C.TypeNaive:
		rawOptionsPtr = &h.NaiveOptions
	case C.TypeHysteria:
		rawOptionsPtr = &h.HysteriaOptions
	case C.TypeShadowTLS:
		rawOptionsPtr = &h.ShadowTLSOptions
	case C.TypeVLESS:
		rawOptionsPtr = &h.VLESSOptions
	case C.TypeTUIC:
		rawOptionsPtr = &h.TUICOptions
	case C.TypeHysteria2:
		rawOptionsPtr = &h.Hysteria2Options
	case "":
		return nil, E.New("missing inbound type")
	default:
		return nil, E.New("unknown inbound type: ", h.Type)
	}
	return rawOptionsPtr, nil
}

func (h Inbound) MarshalJSON() ([]byte, error) {
	rawOptions, err := h.RawOptions()
	if err != nil {
		return nil, err
	}
	return MarshallObjects((_Inbound)(h), rawOptions)
}

func (h *Inbound) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, (*_Inbound)(h))
	if err != nil {
		return err
	}
	rawOptions, err := h.RawOptions()
	if err != nil {
		return err
	}
	err = UnmarshallExcluded(bytes, (*_Inbound)(h), rawOptions)
	if err != nil {
		return err
	}
	return nil
}

func (h *Inbound) GetSniffOverrideRules() []Rule {
	switch h.Type {
	case C.TypeTun:
		return h.TunOptions.GetSniffOverrideRules()
	case C.TypeRedirect:
		return h.RedirectOptions.GetSniffOverrideRules()
	case C.TypeTProxy:
		return h.TProxyOptions.GetSniffOverrideRules()
	case C.TypeDirect:
		return h.DirectOptions.GetSniffOverrideRules()
	case C.TypeSOCKS:
		return h.SocksOptions.GetSniffOverrideRules()
	case C.TypeHTTP:
		return h.HTTPOptions.GetSniffOverrideRules()
	case C.TypeMixed:
		return h.MixedOptions.GetSniffOverrideRules()
	case C.TypeShadowsocks:
		return h.ShadowsocksOptions.GetSniffOverrideRules()
	case C.TypeVMess:
		return h.VMessOptions.GetSniffOverrideRules()
	case C.TypeTrojan:
		return h.TrojanOptions.GetSniffOverrideRules()
	case C.TypeNaive:
		return h.NaiveOptions.GetSniffOverrideRules()
	case C.TypeHysteria:
		return h.HysteriaOptions.GetSniffOverrideRules()
	case C.TypeShadowTLS:
		return h.ShadowTLSOptions.GetSniffOverrideRules()
	case C.TypeVLESS:
		return h.VLESSOptions.GetSniffOverrideRules()
	case C.TypeTUIC:
		return h.TUICOptions.GetSniffOverrideRules()
	case C.TypeHysteria2:
		return h.Hysteria2Options.GetSniffOverrideRules()
	}
	return nil
}

type InboundOptions struct {
	SniffEnabled              bool           `json:"sniff,omitempty"`
	SniffOverrideDestination  bool           `json:"sniff_override_destination,omitempty"`
	SniffOverrideRules        []Rule         `json:"sniff_override_rules,omitempty"`
	SniffTimeout              Duration       `json:"sniff_timeout,omitempty"`
	DomainStrategy            DomainStrategy `json:"domain_strategy,omitempty"`
	UDPDisableDomainUnmapping bool           `json:"udp_disable_domain_unmapping,omitempty"`
}

func (o *InboundOptions) GetSniffOverrideRules() []Rule {
	if !o.SniffEnabled {
		return nil
	}
	if !o.SniffOverrideDestination {
		return nil
	}
	return o.SniffOverrideRules
}

type ListenOptions struct {
	Listen                      *ListenAddress   `json:"listen,omitempty"`
	ListenPort                  uint16           `json:"listen_port,omitempty"`
	TCPFastOpen                 bool             `json:"tcp_fast_open,omitempty"`
	TCPMultiPath                bool             `json:"tcp_multi_path,omitempty"`
	UDPFragment                 *bool            `json:"udp_fragment,omitempty"`
	UDPFragmentDefault          bool             `json:"-"`
	UDPTimeout                  UDPTimeoutCompat `json:"udp_timeout,omitempty"`
	ProxyProtocol               bool             `json:"proxy_protocol,omitempty"`
	ProxyProtocolAcceptNoHeader bool             `json:"proxy_protocol_accept_no_header,omitempty"`
	Detour                      string           `json:"detour,omitempty"`
	InboundOptions
}

type UDPTimeoutCompat Duration

func (c UDPTimeoutCompat) MarshalJSON() ([]byte, error) {
	return json.Marshal((time.Duration)(c).String())
}

func (c *UDPTimeoutCompat) UnmarshalJSON(data []byte) error {
	var valueNumber int64
	err := json.Unmarshal(data, &valueNumber)
	if err == nil {
		*c = UDPTimeoutCompat(time.Second * time.Duration(valueNumber))
		return nil
	}
	return json.Unmarshal(data, (*Duration)(c))
}

type ListenOptionsWrapper interface {
	TakeListenOptions() ListenOptions
	ReplaceListenOptions(options ListenOptions)
}

func (o *ListenOptions) TakeListenOptions() ListenOptions {
	return *o
}

func (o *ListenOptions) ReplaceListenOptions(options ListenOptions) {
	*o = options
}
