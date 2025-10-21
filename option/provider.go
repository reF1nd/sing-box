package option

import (
	"context"

	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/json/badjson"
	"github.com/sagernet/sing/common/json/badoption"
	"github.com/sagernet/sing/service"
)

type ProviderOptionsRegistry interface {
	CreateOptions(providerType string) (any, bool)
}
type _Provider struct {
	Type    string `json:"type"`
	Tag     string `json:"tag,omitempty"`
	Options any    `json:"-"`
}

type Provider _Provider

func (h *Provider) MarshalJSONContext(ctx context.Context) ([]byte, error) {
	return badjson.MarshallObjectsContext(ctx, (*_Provider)(h), h.Options)
}

func (h *Provider) UnmarshalJSONContext(ctx context.Context, content []byte) error {
	err := json.UnmarshalContext(ctx, content, (*_Provider)(h))
	if err != nil {
		return err
	}
	registry := service.FromContext[ProviderOptionsRegistry](ctx)
	if registry == nil {
		return E.New("missing provider options registry in context")
	}
	options, loaded := registry.CreateOptions(h.Type)
	if !loaded {
		return E.New("unknown provider type: ", h.Type)
	}
	err = badjson.UnmarshallExcludedContext(ctx, content, (*_Provider)(h), options)
	if err != nil {
		return err
	}
	h.Options = options
	return nil
}

type ProviderLocalOptions struct {
	Path        string                     `json:"path"`
	HealthCheck ProviderHealthCheckOptions `json:"health_check,omitempty"`

	OverrideDialer *OverrideDialerOptions `json:"override_dialer,omitempty"`
	OverrideTLS    *OverrideTLSOptions    `json:"override_tls,omitempty"`
}

type ProviderRemoteOptions struct {
	URL            string             `json:"url"`
	Path           string             `json:"path,omitempty"`
	UserAgent      string             `json:"user_agent,omitempty"`
	DownloadDetour string             `json:"download_detour,omitempty"`
	UpdateInterval badoption.Duration `json:"update_interval,omitempty"`

	Exclude     *badoption.Regexp          `json:"exclude,omitempty"`
	Include     *badoption.Regexp          `json:"include,omitempty"`
	HealthCheck ProviderHealthCheckOptions `json:"health_check,omitempty"`

	OverrideDialer *OverrideDialerOptions `json:"override_dialer,omitempty"`
	OverrideTLS    *OverrideTLSOptions    `json:"override_tls,omitempty"`
}

type ProviderInlineOptions struct {
	Outbounds   []Outbound                 `json:"outbounds,omitempty"`
	HealthCheck ProviderHealthCheckOptions `json:"health_check,omitempty"`
}

type ProviderHealthCheckOptions struct {
	Enabled  bool               `json:"enabled,omitempty"`
	URL      string             `json:"url,omitempty"`
	Interval badoption.Duration `json:"interval,omitempty"`
	Timeout  badoption.Duration `json:"timeout,omitempty"`
}

type OverrideDialerOptions struct {
	Detour               *string                            `json:"detour,omitempty"`
	BindInterface        *string                            `json:"bind_interface,omitempty"`
	Inet4BindAddress     *badoption.Addr                    `json:"inet4_bind_address,omitempty"`
	Inet6BindAddress     *badoption.Addr                    `json:"inet6_bind_address,omitempty"`
	ProtectPath          *string                            `json:"protect_path,omitempty"`
	RoutingMark          *FwMark                            `json:"routing_mark,omitempty"`
	ReuseAddr            *bool                              `json:"reuse_addr,omitempty"`
	ConnectTimeout       *badoption.Duration                `json:"connect_timeout,omitempty"`
	TCPFastOpen          *bool                              `json:"tcp_fast_open,omitempty"`
	TCPMultiPath         *bool                              `json:"tcp_multi_path,omitempty"`
	UDPFragment          *bool                              `json:"udp_fragment,omitempty"`
	DomainResolver       *DomainResolveOptions              `json:"domain_resolver,omitempty"`
	NetworkStrategy      *NetworkStrategy                   `json:"network_strategy,omitempty"`
	NetworkType          *badoption.Listable[InterfaceType] `json:"network_type,omitempty"`
	FallbackNetworkType  *badoption.Listable[InterfaceType] `json:"fallback_network_type,omitempty"`
	FallbackDelay        *badoption.Duration                `json:"fallback_delay,omitempty"`
	TCPKeepAlive         *badoption.Duration                `json:"tcp_keep_alive,omitempty"`
	TCPKeepAliveInterval *badoption.Duration                `json:"tcp_keep_alive_interval,omitempty"`
	TCPKeepAliveCount    *int                               `json:"tcp_keep_alive_count,omitempty"`
	DisableTCPKeepAlive  *bool                              `json:"disable_tcp_keep_alive,omitempty"`

	// Deprecated: migrated to domain resolver
	DomainStrategy *DomainStrategy `json:"domain_strategy,omitempty"`
}

type OverrideTLSOptions struct {
	Enabled               *bool                       `json:"enabled,omitempty"`
	DisableSNI            *bool                       `json:"disable_sni,omitempty"`
	ServerName            *string                     `json:"server_name,omitempty"`
	Insecure              *bool                       `json:"insecure,omitempty"`
	ALPN                  *badoption.Listable[string] `json:"alpn,omitempty"`
	MinVersion            *string                     `json:"min_version,omitempty"`
	MaxVersion            *string                     `json:"max_version,omitempty"`
	CipherSuites          *badoption.Listable[string] `json:"cipher_suites,omitempty"`
	Certificate           *badoption.Listable[string] `json:"certificate,omitempty"`
	CertificatePath       *string                     `json:"certificate_path,omitempty"`
	CertificatePinSHA256  *string                     `json:"certificate_pin_sha256,omitempty"`
	Fragment              *bool                       `json:"fragment,omitempty"`
	FragmentFallbackDelay *badoption.Duration         `json:"fragment_fallback_delay,omitempty"`
	RecordFragment        *bool                       `json:"record_fragment,omitempty"`
	ECH                   *OverrideECHOptions         `json:"ech,omitempty"`
	UTLS                  *OverrideUTLSOptions        `json:"utls,omitempty"`
	Reality               *OverrideRealityOptions     `json:"reality,omitempty"`
}

type OverrideECHOptions struct {
	Enabled    *bool                       `json:"enabled,omitempty"`
	Config     *badoption.Listable[string] `json:"config,omitempty"`
	ConfigPath *string                     `json:"config_path,omitempty"`

	// Deprecated: not supported by stdlib
	PQSignatureSchemesEnabled *bool `json:"pq_signature_schemes_enabled,omitempty"`
	// Deprecated: added by fault
	DynamicRecordSizingDisabled *bool `json:"dynamic_record_sizing_disabled,omitempty"`
}

type OverrideUTLSOptions struct {
	Enabled     *bool   `json:"enabled,omitempty"`
	Fingerprint *string `json:"fingerprint,omitempty"`
}

type OverrideRealityOptions struct {
	Enabled   *bool   `json:"enabled,omitempty"`
	PublicKey *string `json:"public_key,omitempty"`
	ShortID   *string `json:"short_id,omitempty"`
}
