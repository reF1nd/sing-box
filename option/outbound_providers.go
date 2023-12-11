package option

import (
	C "github.com/sagernet/sing-box/constant"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
)

type _OutboundProvider struct {
	Type                string                 `json:"type"`
	Path                string                 `json:"path"`
	Tag                 string                 `json:"tag,omitempty"`
	HealthcheckUrl      string                 `json:"healthcheck_url,omitempty"`
	HealthcheckInterval Duration               `json:"healthcheck_interval,omitempty"`
	OverrideDialer      *OverrideDialerOptions `json:"override_dialer,omitempty"`
	RemoteOptions       RemoteProviderOptions  `json:"-"`
	FilterOptions
}

type OutboundProvider _OutboundProvider

type OverrideDialerOptions struct {
	ForceOverride    bool            `json:"force_override,omitempty"`
	Detour           *string         `json:"detour,omitempty"`
	BindInterface    *string         `json:"bind_interface,omitempty"`
	Inet4BindAddress *ListenAddress  `json:"inet4_bind_address,omitempty"`
	Inet6BindAddress *ListenAddress  `json:"inet6_bind_address,omitempty"`
	ProtectPath      *string         `json:"protect_path,omitempty"`
	RoutingMark      *int            `json:"routing_mark,omitempty"`
	ReuseAddr        *bool           `json:"reuse_addr,omitempty"`
	ConnectTimeout   *Duration       `json:"connect_timeout,omitempty"`
	TCPFastOpen      *bool           `json:"tcp_fast_open,omitempty"`
	TCPMultiPath     *bool           `json:"tcp_multi_path,omitempty"`
	UDPFragment      *bool           `json:"udp_fragment,omitempty"`
	DomainStrategy   *DomainStrategy `json:"domain_strategy,omitempty"`
	FallbackDelay    *Duration       `json:"fallback_delay,omitempty"`
	ResolveUDP       *bool           `json:"always_resolve_udp,omitempty"`
}

type RemoteProviderOptions struct {
	Url       string   `json:"download_url"`
	UserAgent string   `json:"download_ua,omitempty"`
	Interval  Duration `json:"download_interval,omitempty"`
	Detour    string   `json:"download_detour,omitempty"`
}

func (h OutboundProvider) MarshalJSON() ([]byte, error) {
	var v any
	switch h.Type {
	case C.TypeLocalProvider:
		v = nil
	case C.TypeRemoteProvider:
		v = h.RemoteOptions
	default:
		return nil, E.New("unknown provider type: ", h.Type)
	}
	return MarshallObjects((_OutboundProvider)(h), v)
}

func (h *OutboundProvider) UnmarshalJSON(bytes []byte) error {
	err := json.Unmarshal(bytes, (*_OutboundProvider)(h))
	if err != nil {
		return err
	}
	var v any
	switch h.Type {
	case C.TypeLocalProvider:
		v = nil
	case C.TypeRemoteProvider:
		v = &h.RemoteOptions
	default:
		return E.New("unknown provider type: ", h.Type)
	}
	err = UnmarshallExcluded(bytes, (*_OutboundProvider)(h), v)
	if err != nil {
		return E.Cause(err, "provider options")
	}
	return nil
}
