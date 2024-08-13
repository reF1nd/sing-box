package adapter

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/sagernet/sing-box/common/geoip"
	C "github.com/sagernet/sing-box/constant"
	dns "github.com/sagernet/sing-dns"
	tun "github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common/control"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	mdns "github.com/miekg/dns"
	"go4.org/netipx"
)

type Router interface {
	Service
	PreStarter
	PostStarter
	Cleanup() error

	Outbounds() []Outbound
	Outbound(tag string) (Outbound, bool)
	OutboundsWithProvider() []Outbound
	OutboundWithProvider(tag string) (Outbound, bool)
	DefaultOutbound(network string) (Outbound, error)

	OutboundProviders() []OutboundProvider
	OutboundProvider(tag string) (OutboundProvider, bool)

	FakeIPStore() FakeIPStore

	ConnectionRouter

	GeoIPReader() *geoip.Reader
	LoadGeosite(code string) (Rule, error)
	UpdateGeoDatabase()

	RuleSets() []RuleSet
	RuleSet(tag string) (RuleSet, bool)

	NeedWIFIState() bool

	Exchange(ctx context.Context, message *mdns.Msg) (*mdns.Msg, error)
	Lookup(ctx context.Context, domain string, strategy dns.DomainStrategy) ([]netip.Addr, error)
	LookupDefault(ctx context.Context, domain string) ([]netip.Addr, error)
	ClearDNSCache()

	InterfaceFinder() control.InterfaceFinder
	UpdateInterfaces() error
	DefaultInterface() string
	AutoDetectInterface() bool
	AutoDetectInterfaceFunc() control.Func
	DefaultMark() uint32
	RegisterAutoRedirectOutputMark(mark uint32) error
	AutoRedirectOutputMark() uint32
	NetworkMonitor() tun.NetworkUpdateMonitor
	InterfaceMonitor() tun.DefaultInterfaceMonitor
	PackageManager() tun.PackageManager
	WIFIState() WIFIState
	Rules() []Rule
	Rule(uuid string) (Rule, bool)
	DNSRules() []DNSRule
	DNSRule(uuid string) (DNSRule, bool)
	DefaultDNSServer() string

	ClashServer() ClashServer
	SetClashServer(server ClashServer)

	V2RayServer() V2RayServer
	SetV2RayServer(server V2RayServer)

	ResetNetwork() error

	Reload()
}

func ContextWithRouter(ctx context.Context, router Router) context.Context {
	return service.ContextWith(ctx, router)
}

func RouterFromContext(ctx context.Context) Router {
	return service.FromContext[Router](ctx)
}

type HeadlessRule interface {
	Match(metadata *InboundContext) bool
	RuleCount() uint64
	String() string
}

type Rule interface {
	HeadlessRule
	Service
	Disabled() bool
	UUID() string
	ChangeStatus()
	Type() string
	UpdateGeosite() error
	Outbound() string
}

type DNSRule interface {
	Rule
	DisableCache() bool
	RewriteTTL() *uint32
	ClientSubnet() *netip.Prefix
	WithAddressLimit() bool
	MatchAddressLimit(metadata *InboundContext) bool
}

type RuleSet interface {
	Name() string
	Type() string
	Format() string
	UpdatedTime() time.Time
	Update(ctx context.Context) error
	StartContext(ctx context.Context, startContext *HTTPStartContext) error
	PostStart() error
	Metadata() RuleSetMetadata
	ExtractIPSet() []*netipx.IPSet
	IncRef()
	DecRef()
	Cleanup()
	RegisterCallback(callback RuleSetUpdateCallback) *list.Element[RuleSetUpdateCallback]
	UnregisterCallback(element *list.Element[RuleSetUpdateCallback])
	Close() error
	HeadlessRule
}

type RuleSetUpdateCallback func(it RuleSet)

type RuleSetMetadata struct {
	ContainsProcessRule bool
	ContainsWIFIRule    bool
	ContainsIPCIDRRule  bool
}
type HTTPStartContext struct {
	access          sync.Mutex
	httpClientCache map[string]*http.Client
}

func NewHTTPStartContext() *HTTPStartContext {
	return &HTTPStartContext{
		httpClientCache: make(map[string]*http.Client),
	}
}

func (c *HTTPStartContext) HTTPClient(detour string, dialer N.Dialer) *http.Client {
	c.access.Lock()
	defer c.access.Unlock()
	if httpClient, loaded := c.httpClientCache[detour]; loaded {
		return httpClient
	}
	httpClient := &http.Client{
		Transport: &http.Transport{
			ForceAttemptHTTP2:   true,
			TLSHandshakeTimeout: C.TCPTimeout,
			DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, M.ParseSocksaddr(addr))
			},
		},
	}
	c.httpClientCache[detour] = httpClient
	return httpClient
}

func (c *HTTPStartContext) Close() {
	c.access.Lock()
	defer c.access.Unlock()
	for _, client := range c.httpClientCache {
		client.CloseIdleConnections()
	}
}

type InterfaceUpdateListener interface {
	InterfaceUpdated()
}

type WIFIState struct {
	SSID  string
	BSSID string
}
