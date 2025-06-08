package box_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/json"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
	"github.com/stretchr/testify/require"
)

func TestInlineProviderInitialMembers(t *testing.T) {
	for _, groupType := range []string{"selector", "urltest", "loadbalance"} {
		t.Run(groupType, func(t *testing.T) {
			ctx := include.Context(context.Background())
			options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(fmt.Sprintf(`{
    "log":{"disabled":true},
    "outbounds":[{"type":%q,"tag":"select","providers":["p"]}],
    "providers":[{"type":"inline","tag":"p","outbounds":[{"type":"socks","tag":"node","server":"127.0.0.1","server_port":9}]}]
   }`, groupType)))
			require.NoError(t, err)
			instance, err := box.New(box.Options{Context: ctx, Options: options})
			require.NoError(t, err)
			defer instance.Close()
			require.NoError(t, instance.Start())
			manager := service.FromContext[adapter.OutboundManager](ctx)
			selected, found := manager.Outbound("select")
			require.True(t, found)
			require.Equal(t, []string{"p/node"}, selected.(adapter.OutboundGroup).All())
			if groupType == "selector" {
				require.Equal(t, "p/node", selected.(adapter.OutboundGroup).Selected("tcp").Tag())
			}
			require.NoError(t, instance.Close())
		})
	}
}

func TestSelectorDefaultFromProviderColdStart(t *testing.T) {
	for _, testCase := range []struct {
		name      string
		outbounds string
		defaultTo string
		expected  string
		err       string
	}{
		{name: "provider only", outbounds: `[]`, defaultTo: "p/second", expected: "p/second"},
		{name: "mixed", outbounds: `["bootstrap"]`, defaultTo: "p/second", expected: "p/second"},
		{name: "missing", outbounds: `["bootstrap"]`, defaultTo: "p/missing", expected: "bootstrap"},
		{name: "bare tag", outbounds: `["bootstrap"]`, defaultTo: "second", err: "default outbound not found: second"},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "subscription.json")
			require.NoError(t, os.WriteFile(path, []byte(`{"outbounds":[{"type":"socks","tag":"first","server":"127.0.0.1","server_port":9},{"type":"socks","tag":"second","server":"127.0.0.1","server_port":10}]}`), 0o600))
			ctx := include.Context(t.Context())
			options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(fmt.Sprintf(`{
 "log":{"disabled":true},
 "outbounds":[
  {"type":"direct","tag":"bootstrap"},
  {"type":"selector","tag":"select","outbounds":%s,"providers":["p"],"default":%q}
 ],
 "providers":[{"type":"local","tag":"p","path":%q}]
 }`, testCase.outbounds, testCase.defaultTo, path)))
			require.NoError(t, err)
			instance, err := box.New(box.Options{Context: ctx, Options: options})
			require.NoError(t, err)
			defer instance.Close()
			err = instance.Start()
			if testCase.err != "" {
				require.ErrorContains(t, err, testCase.err)
				return
			}
			require.NoError(t, err)
			manager := service.FromContext[adapter.OutboundManager](ctx)
			group, found := manager.Outbound("select")
			require.True(t, found)
			require.Equal(t, testCase.expected, group.(adapter.OutboundGroup).Selected("tcp").Tag())
			require.NoError(t, instance.Close())
		})
	}
}

func TestSelectorInlineDefaultForFirstProviderDownload(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"outbounds":[{"type":"socks","tag":"node","server":"127.0.0.1","server_port":9}]}`)
	}))
	defer server.Close()
	// The remote provider downloads before the inline provider's first callback.
	// Only the choice of default changes whether its HTTP request can reach the server.
	for _, defaultTag := range []string{"seed/allow", "seed/deny"} {
		t.Run(defaultTag, func(t *testing.T) {
			ctx := include.Context(t.Context())
			options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(fmt.Sprintf(`{
 "log":{"disabled":true},
 "outbounds":[{"type":"selector","tag":"select","providers":["seed"],"default":%q}],
 "providers":[
  {"type":"remote","tag":"remote","url":%q,"http_client":{"detour":"select"}},
  {"type":"inline","tag":"seed","outbounds":[{"type":"block","tag":"deny"},{"type":"direct","tag":"allow"}]}
 ]
 }`, defaultTag, server.URL)))
			require.NoError(t, err)
			instance, err := box.New(box.Options{Context: ctx, Options: options})
			require.NoError(t, err)
			defer instance.Close()
			err = instance.PreStart()
			if defaultTag == "seed/deny" {
				require.ErrorIs(t, err, syscall.EPERM)
				return
			}
			require.NoError(t, err)
			_, found := service.FromContext[adapter.OutboundManager](ctx).Outbound("remote/node")
			require.True(t, found)
		})
	}
}

// PreStart never reaches the post-start stage, so the provider manager must
// end the initial selection itself, or a default appearing later would win.
func TestSelectorProviderSelectionFinalizedInPreStart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subscription.json")
	content := func(tags ...string) []byte {
		var outbounds []string
		for i, tag := range tags {
			outbounds = append(outbounds, fmt.Sprintf(`{"type":"socks","tag":%q,"server":"127.0.0.1","server_port":%d}`, tag, 10+i))
		}
		return []byte(`{"outbounds":[` + strings.Join(outbounds, ",") + `]}`)
	}
	require.NoError(t, os.WriteFile(path, content("first"), 0o600))
	ctx := include.Context(t.Context())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(fmt.Sprintf(`{
 "log":{"disabled":true},
 "outbounds":[{"type":"selector","tag":"select","providers":["p"],"default":"p/second"}],
 "providers":[{"type":"local","tag":"p","path":%q}]
 }`, path)))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.PreStart())
	manager := service.FromContext[adapter.OutboundManager](ctx)
	// A group created after PreStart has already missed the initial provider load.
	err = manager.(adapter.DynamicOutboundManager).Replace(ctx, instance.Router(), instance.LogFactory().Logger(), "late", "selector", options.Outbounds[0].Options)
	require.NoError(t, err)
	var groups []adapter.OutboundGroup
	for _, tag := range []string{"select", "late"} {
		outbound, found := manager.Outbound(tag)
		require.True(t, found)
		group := outbound.(adapter.OutboundGroup)
		require.Equal(t, "p/first", group.Selected("tcp").Tag())
		groups = append(groups, group)
	}
	require.NoError(t, os.WriteFile(path, content("first", "second"), 0o600))
	for _, group := range groups {
		require.Eventually(t, func() bool { return slices.Contains(group.All(), "p/second") }, 3*time.Second, 10*time.Millisecond)
		require.Equal(t, "p/first", group.Selected("tcp").Tag())
	}
	require.NoError(t, instance.Close())
}

func TestLocalProviderUpdatesWithoutReplacingBoxComponents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "subscription.json")
	content := func(port int) []byte {
		return []byte(fmt.Sprintf(`{"outbounds":[{"type":"socks","tag":"stable","server":"127.0.0.1","server_port":9},{"type":"socks","tag":"changed","server":"127.0.0.1","server_port":%d}]}`, port))
	}
	require.NoError(t, os.WriteFile(path, content(10), 0600))
	ctx := include.Context(context.Background())
	options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(fmt.Sprintf(`{
 "log":{"disabled":true},
 "outbounds":[{"type":"selector","tag":"select","providers":["p"]}],
 "providers":[{"type":"local","tag":"p","path":%q}]
 }`, path)))
	require.NoError(t, err)
	instance, err := box.New(box.Options{Context: ctx, Options: options})
	require.NoError(t, err)
	defer instance.Close()
	require.NoError(t, instance.Start())
	manager := service.FromContext[adapter.OutboundManager](ctx)
	group, _ := manager.Outbound("select")
	stable, _ := manager.Outbound("p/stable")
	previous, _ := manager.Outbound("p/changed")
	require.Equal(t, []string{"p/stable", "p/changed"}, group.(adapter.OutboundGroup).All())
	for _, port := range []int{11, 12, 13} {
		require.NoError(t, os.WriteFile(path, content(port), 0600))
		require.Eventually(t, func() bool { current, ok := manager.Outbound("p/changed"); return ok && current != previous }, 3*time.Second, 10*time.Millisecond)
		previous, _ = manager.Outbound("p/changed")
		same, _ := manager.Outbound("p/stable")
		require.Same(t, stable, same)
		sameGroup, _ := manager.Outbound("select")
		require.Same(t, group, sameGroup)
		require.Same(t, manager, service.FromContext[adapter.OutboundManager](ctx))
		require.Same(t, stable, group.(adapter.OutboundGroup).Selected("tcp"))
	}
	require.NoError(t, instance.Close())
}

func TestGroupProviderFirstDownload(t *testing.T) {
	for _, groupType := range []string{"selector", "urltest", "loadbalance"} {
		for _, memberType := range []string{"block", "direct"} {
			t.Run(groupType+"/"+memberType, func(t *testing.T) {
				var subscriptionRequests atomic.Int32
				mux := http.NewServeMux()
				mux.HandleFunc("/subscription", func(w http.ResponseWriter, r *http.Request) {
					subscriptionRequests.Add(1)
					_, _ = io.WriteString(w, `{"outbounds":[{"type":"socks","tag":"node","server":"127.0.0.1","server_port":9}]}`)
				})
				mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				})
				server := httptest.NewServer(mux)
				defer server.Close()

				groupConfig := fmt.Sprintf(`{"type":%q,"tag":"group","providers":["seed"]}`, groupType)
				if groupType != "selector" {
					groupConfig = fmt.Sprintf(`{"type":%q,"tag":"group","providers":["seed"],"url":%q}`, groupType, server.URL+"/probe")
				}
				ctx := include.Context(t.Context())
				// The remote provider downloads before the inline provider's first callback.
				options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(fmt.Sprintf(`{
 "log":{"disabled":true},
 "outbounds":[%s],
 "providers":[
  {"type":"remote","tag":"remote","url":%q,"http_client":{"detour":"group"}},
  {"type":"inline","tag":"seed","outbounds":[{"type":%q,"tag":"member"}]}
 ]
 }`, groupConfig, server.URL+"/subscription", memberType)))
				require.NoError(t, err)
				instance, err := box.New(box.Options{Context: ctx, Options: options})
				require.NoError(t, err)
				defer instance.Close()
				err = instance.PreStart()
				if memberType == "block" {
					require.ErrorIs(t, err, syscall.EPERM)
					require.Zero(t, subscriptionRequests.Load())
					return
				}
				require.NoError(t, err)
				require.Equal(t, int32(1), subscriptionRequests.Load())
				_, found := service.FromContext[adapter.OutboundManager](ctx).Outbound("remote/node")
				require.True(t, found)
			})
		}
	}
}

func TestGroupProviderMembersAfterPreStart(t *testing.T) {
	for _, groupType := range []string{"selector", "urltest", "loadbalance"} {
		for _, testCase := range []struct {
			name        string
			extraFields string
			expected    []string
		}{
			{
				name:     "provider only",
				expected: []string{"seed/member"},
			},
			{
				name:        "mixed",
				extraFields: `,"outbounds":["bootstrap"],"include":"/member$"`,
				expected:    []string{"bootstrap", "seed/member"},
			},
		} {
			t.Run(groupType+"/"+testCase.name, func(t *testing.T) {
				ctx := include.Context(t.Context())
				seedOutbounds := `[{"type":"block","tag":"member"}]`
				if testCase.name == "mixed" {
					seedOutbounds = `[{"type":"block","tag":"member"},{"type":"block","tag":"ignored"}]`
				}
				options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(fmt.Sprintf(`{
 "log":{"disabled":true},
 "outbounds":[{"type":"direct","tag":"bootstrap"}],
 "providers":[{"type":"inline","tag":"seed","outbounds":%s}]
 }`, seedOutbounds)))
				require.NoError(t, err)
				instance, err := box.New(box.Options{Context: ctx, Options: options})
				require.NoError(t, err)
				defer instance.Close()
				require.NoError(t, instance.PreStart())

				providers := service.FromContext[adapter.ProviderManager](ctx)
				seed, found := providers.Get("seed")
				require.True(t, found)
				require.NotEmpty(t, seed.Outbounds())

				lateOutbound, err := json.UnmarshalExtendedContext[option.Outbound](ctx, []byte(fmt.Sprintf(
					`{"type":%q,"tag":"late","providers":["seed"]%s}`,
					groupType, testCase.extraFields,
				)))
				require.NoError(t, err)
				manager := service.FromContext[adapter.OutboundManager](ctx)
				err = manager.(adapter.DynamicOutboundManager).Replace(
					ctx,
					instance.Router(),
					instance.LogFactory().Logger(),
					"late",
					groupType,
					lateOutbound.Options,
				)
				require.NoError(t, err)
				group, found := manager.Outbound("late")
				require.True(t, found)
				require.Equal(t, testCase.expected, group.(adapter.OutboundGroup).All())
			})
		}
	}
}

type startDialTestOptions struct {
	Detour string `json:"detour"`
	Target string `json:"target"`
}

type startDialTestOutbound struct {
	outbound.Adapter
	ctx      context.Context
	outbound adapter.OutboundManager
	detour   string
	target   string
}

func (o *startDialTestOutbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	detour, loaded := o.outbound.Outbound(o.detour)
	if !loaded {
		return E.New("detour not found: ", o.detour)
	}
	transport := &http.Transport{
		DialContext: func(ctx context.Context, network string, addr string) (net.Conn, error) {
			return detour.DialContext(ctx, network, M.ParseSocksaddr(addr))
		},
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(o.ctx, http.MethodGet, o.target, nil)
	if err != nil {
		return err
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return E.New("unexpected status: ", response.StatusCode)
	}
	_, err = io.Copy(io.Discard, response.Body)
	return err
}

func (o *startDialTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return nil, os.ErrInvalid
}

func (o *startDialTestOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

type recordDialTestOutbound struct {
	outbound.Adapter
	hits *atomic.Int32
}

func (o *recordDialTestOutbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	o.hits.Add(1)
	var dialer net.Dialer
	return dialer.DialContext(ctx, network, destination.String())
}

func (o *recordDialTestOutbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return nil, os.ErrInvalid
}

func TestGroupProviderMemberStartupOrder(t *testing.T) {
	for _, groupType := range []string{"selector", "urltest", "loadbalance"} {
		for _, binding := range []struct {
			name   string
			fields string
		}{
			{name: "providers", fields: `"providers":["seed"]`},
			{name: "use_all_providers", fields: `"use_all_providers":true`},
		} {
			t.Run(groupType+"/"+binding.name, func(t *testing.T) {
				var targetHits atomic.Int32
				var innerHits atomic.Int32
				mux := http.NewServeMux()
				mux.HandleFunc("/target", func(w http.ResponseWriter, r *http.Request) {
					targetHits.Add(1)
					_, _ = io.WriteString(w, "ok")
				})
				mux.HandleFunc("/probe", func(w http.ResponseWriter, r *http.Request) {
					w.WriteHeader(http.StatusNoContent)
				})
				server := httptest.NewServer(mux)
				defer server.Close()

				ctx := include.Context(t.Context())
				registry := service.FromContext[adapter.OutboundRegistry](ctx).(*outbound.Registry)
				outbound.Register[option.StubOptions](registry, "record-dial-test", func(_ context.Context, _ adapter.Router, _ log.ContextLogger, tag string, _ option.StubOptions) (adapter.Outbound, error) {
					return &recordDialTestOutbound{
						Adapter: outbound.NewAdapter("record-dial-test", tag, []string{N.NetworkTCP}, nil),
						hits:    &innerHits,
					}, nil
				})
				outbound.Register[startDialTestOptions](registry, "start-dial-test", func(ctx context.Context, _ adapter.Router, _ log.ContextLogger, tag string, options startDialTestOptions) (adapter.Outbound, error) {
					return &startDialTestOutbound{
						Adapter:  outbound.NewAdapter("start-dial-test", tag, []string{N.NetworkTCP}, []string{options.Detour}),
						ctx:      ctx,
						outbound: service.FromContext[adapter.OutboundManager](ctx),
						detour:   options.Detour,
						target:   options.Target,
					}, nil
				})

				outerConfig := fmt.Sprintf(`{"type":%q,"tag":"outer",%s}`, groupType, binding.fields)
				if groupType != "selector" {
					outerConfig = fmt.Sprintf(`{"type":%q,"tag":"outer",%s,"url":%q}`, groupType, binding.fields, server.URL+"/probe")
				}
				// An outbound that dials through the outer group during StartStateStart must
				// see inline nested-group members already started.
				options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(fmt.Sprintf(`{
 "log":{"disabled":true},
 "outbounds":[
  {"type":"record-dial-test","tag":"bootstrap"},
  %s,
  {"type":"start-dial-test","tag":"early","detour":"outer","target":%q}
 ],
 "providers":[
  {"type":"inline","tag":"seed","outbounds":[{"type":"urltest","tag":"inner","outbounds":["bootstrap"],"url":%q}]}
 ]
 }`, outerConfig, server.URL+"/target", server.URL+"/probe")))
				require.NoError(t, err)
				instance, err := box.New(box.Options{Context: ctx, Options: options})
				require.NoError(t, err)
				defer instance.Close()
				require.NoError(t, instance.PreStart())
				require.Equal(t, int32(1), innerHits.Load())
				require.Equal(t, int32(1), targetHits.Load())
			})
		}
	}
}

func TestGroupProviderSelfMember(t *testing.T) {
	for _, groupType := range []string{"selector", "urltest", "loadbalance"} {
		t.Run(groupType, func(t *testing.T) {
			ctx := include.Context(t.Context())
			// Put the self-binding group before the normal node so including itself
			// would also expose self-selection/recursion immediately.
			options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(fmt.Sprintf(`{
 "log":{"disabled":true},
 "providers":[
  {"type":"inline","tag":"earlier"},
  {"type":"inline","tag":"seed","outbounds":[
   {"type":%q,"tag":"inner","use_all_providers":true},
   {"type":"socks","tag":"member","server":"127.0.0.1","server_port":9}
  ]}
 ]
 }`, groupType)))
			require.NoError(t, err)
			instance, err := box.New(box.Options{Context: ctx, Options: options})
			require.NoError(t, err)
			defer instance.Close()

			manager := service.FromContext[adapter.OutboundManager](ctx)
			providers := service.FromContext[adapter.ProviderManager](ctx)
			earlier, found := providers.Get("earlier")
			require.True(t, found)

			var initialMembers []string
			var initialSelected string
			callback := earlier.RegisterCallback(func(string) error {
				inner, ok := manager.Outbound("seed/inner")
				require.True(t, ok)
				group := inner.(adapter.OutboundGroup)
				initialMembers = group.All()
				if groupType != "loadbalance" {
					initialSelected = group.Selected("tcp").Tag()
				}
				return nil
			})
			defer earlier.UnregisterCallback(callback)

			require.NoError(t, instance.PreStart())
			require.Equal(t, []string{"seed/member"}, initialMembers)
			if groupType != "loadbalance" {
				require.Equal(t, "seed/member", initialSelected)
			}

			inner, found := manager.Outbound("seed/inner")
			require.True(t, found)
			group := inner.(adapter.OutboundGroup)
			require.Equal(t, []string{"seed/member"}, group.All())
			if groupType != "loadbalance" {
				require.Equal(t, "seed/member", group.Selected("tcp").Tag())
			}
		})
	}
}

func TestCompatibleFallbackAndImplicitDirect(t *testing.T) {
	t.Run("empty config keeps implicit direct and exposes Compatible", func(t *testing.T) {
		ctx := include.Context(t.Context())
		options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
 "log":{"disabled":true},
 "route":{"rules":[{"outbound":"direct"}]}
 }`))
		require.NoError(t, err)
		instance, err := box.New(box.Options{Context: ctx, Options: options})
		require.NoError(t, err)
		defer instance.Close()
		require.NoError(t, instance.Start())

		manager := service.FromContext[adapter.OutboundManager](ctx)
		require.Equal(t, "direct", manager.Default().Tag())
		_, found := manager.Outbound("direct")
		require.True(t, found)
		compatible, found := manager.Outbound("Compatible")
		require.True(t, found)
		require.Equal(t, "direct", compatible.Type())
		require.Len(t, manager.Outbounds(), 1)
		require.Equal(t, "direct", manager.Outbounds()[0].Tag())
		require.NoError(t, instance.Close())
	})

	t.Run("first static outbound remains default and explicit Compatible final works", func(t *testing.T) {
		ctx := include.Context(t.Context())
		options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
 "log":{"disabled":true},
 "outbounds":[{"type":"socks","tag":"first","server":"127.0.0.1","server_port":9}]
 }`))
		require.NoError(t, err)
		instance, err := box.New(box.Options{Context: ctx, Options: options})
		require.NoError(t, err)
		defer instance.Close()
		require.Equal(t, "first", instance.Outbound().Default().Tag())
		_, found := instance.Outbound().Outbound("Compatible")
		require.True(t, found)

		ctx2 := include.Context(t.Context())
		options2, err := json.UnmarshalExtendedContext[option.Options](ctx2, []byte(`{
 "log":{"disabled":true},
 "outbounds":[{"type":"socks","tag":"first","server":"127.0.0.1","server_port":9}],
 "route":{"final":"Compatible"}
 }`))
		require.NoError(t, err)
		instance2, err := box.New(box.Options{Context: ctx2, Options: options2})
		require.NoError(t, err)
		defer instance2.Close()
		require.NoError(t, instance2.Start())
		require.Equal(t, "Compatible", instance2.Outbound().Default().Tag())
		require.NoError(t, instance2.Close())
	})

	t.Run("user defined Compatible outbound overrides implicit fallback", func(t *testing.T) {
		ctx := include.Context(t.Context())
		options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
 "log":{"disabled":true},
 "outbounds":[
  {"type":"block","tag":"Compatible"},
  {"type":"selector","tag":"select","providers":["empty"]}
 ],
 "providers":[{"type":"inline","tag":"empty"}]
 }`))
		require.NoError(t, err)
		instance, err := box.New(box.Options{Context: ctx, Options: options})
		require.NoError(t, err)
		defer instance.Close()
		require.NoError(t, instance.Start())

		manager := service.FromContext[adapter.OutboundManager](ctx)
		compatible, found := manager.Outbound("Compatible")
		require.True(t, found)
		require.Equal(t, "block", compatible.Type())
		group, found := manager.Outbound("select")
		require.True(t, found)
		require.Equal(t, []string{"Compatible"}, group.(adapter.OutboundGroup).All())
		require.Equal(t, "block", group.(adapter.OutboundGroup).Selected("tcp").Type())
		require.NoError(t, instance.Close())
	})

	t.Run("user defined Compatible endpoint overrides implicit fallback", func(t *testing.T) {
		ctx := include.Context(t.Context())
		options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
 "log":{"disabled":true},
 "endpoints":[
  {"type":"wireguard","tag":"Compatible","address":["10.0.0.2/32"],"private_key":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
 ],
 "outbounds":[
  {"type":"selector","tag":"select","providers":["empty"]}
 ],
 "providers":[{"type":"inline","tag":"empty"}]
 }`))
		require.NoError(t, err)
		instance, err := box.New(box.Options{Context: ctx, Options: options})
		require.NoError(t, err)
		defer instance.Close()
		compatible, found := instance.Outbound().Outbound("Compatible")
		require.True(t, found)
		require.Equal(t, "wireguard", compatible.Type())
	})

	t.Run("user defined empty Compatible group rejects self fallback", func(t *testing.T) {
		ctx := include.Context(t.Context())
		options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
 "log":{"disabled":true},
 "outbounds":[
  {"type":"selector","tag":"Compatible","providers":["empty"]}
 ],
 "providers":[{"type":"inline","tag":"empty"}]
 }`))
		require.NoError(t, err)
		instance, err := box.New(box.Options{Context: ctx, Options: options})
		require.NoError(t, err)
		defer instance.Close()
		err = instance.Start()
		require.ErrorContains(t, err, "Compatible cannot reference itself")
	})
}

func TestProviderRouteValidationTiming(t *testing.T) {
	t.Run("box.New rejects typos, unknown providers, missing inline nodes, and missing DNS servers", func(t *testing.T) {
		for _, testCase := range []struct {
			name   string
			config string
			errStr string
		}{
			{
				name:   "plain typo",
				config: `{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"d"}],"route":{"rules":[{"outbound":"missing"}]}}`,
				errStr: "outbound not found: missing",
			},
			{
				name:   "unknown provider prefix",
				config: `{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"d"}],"route":{"rules":[{"outbound":"unknown/node"}]}}`,
				errStr: "outbound not found: unknown/node",
			},
			{
				name: "missing inline provider node",
				config: `{
 "log":{"disabled":true},
 "outbounds":[{"type":"direct","tag":"d"}],
 "providers":[{"type":"inline","tag":"in","outbounds":[{"type":"socks","tag":"real","server":"127.0.0.1","server_port":9}]}],
 "route":{"rules":[{"outbound":"in/missing"}]}
 }`,
				errStr: "outbound not found: in/missing",
			},
			{
				name:   "missing resolve DNS server",
				config: `{"log":{"disabled":true},"outbounds":[{"type":"direct","tag":"d"}],"route":{"rules":[{"action":"resolve","server":"no-dns"}]}}`,
				errStr: "DNS server not found: no-dns",
			},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				ctx := include.Context(t.Context())
				options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(testCase.config))
				require.NoError(t, err)
				_, err = box.New(box.Options{Context: ctx, Options: options})
				require.ErrorContains(t, err, testCase.errStr)
			})
		}
	})

	t.Run("inline provider node validates at box.New", func(t *testing.T) {
		ctx := include.Context(t.Context())
		options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(`{
 "log":{"disabled":true},
 "outbounds":[{"type":"direct","tag":"d"}],
 "providers":[{"type":"inline","tag":"in","outbounds":[{"type":"socks","tag":"real","server":"127.0.0.1","server_port":9}]}],
 "route":{"rules":[{"outbound":"in/real"}]}
 }`))
		require.NoError(t, err)
		instance, err := box.New(box.Options{Context: ctx, Options: options})
		require.NoError(t, err)
		defer instance.Close()
		require.NoError(t, instance.PreStart())
	})

	t.Run("local provider node validation is deferred until after initial load", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "subscription.json")
		require.NoError(t, os.WriteFile(path, []byte(`{"outbounds":[{"type":"socks","tag":"real","server":"127.0.0.1","server_port":9}]}`), 0o600))

		for _, testCase := range []struct {
			name      string
			target    string
			expectErr string
		}{
			{name: "present node", target: "p/real"},
			{name: "missing node", target: "p/missing", expectErr: "outbound not found: p/missing"},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				ctx := include.Context(t.Context())
				options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(fmt.Sprintf(`{
 "log":{"disabled":true},
 "outbounds":[{"type":"direct","tag":"d"}],
 "providers":[{"type":"local","tag":"p","path":%q}],
 "route":{"rules":[{"outbound":%q}]}
 }`, path, testCase.target)))
				require.NoError(t, err)
				instance, err := box.New(box.Options{Context: ctx, Options: options})
				require.NoError(t, err)
				defer instance.Close()
				err = instance.PreStart()
				if testCase.expectErr != "" {
					require.ErrorContains(t, err, testCase.expectErr)
					return
				}
				require.NoError(t, err)
			})
		}
	})

	t.Run("remote provider node validation is deferred until after initial load", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = io.WriteString(w, `{"outbounds":[{"type":"socks","tag":"real","server":"127.0.0.1","server_port":9}]}`)
		}))
		defer server.Close()

		for _, testCase := range []struct {
			name      string
			target    string
			expectErr string
		}{
			{name: "present node", target: "r/real"},
			{name: "missing node", target: "r/missing", expectErr: "outbound not found: r/missing"},
		} {
			t.Run(testCase.name, func(t *testing.T) {
				ctx := include.Context(t.Context())
				options, err := json.UnmarshalExtendedContext[option.Options](ctx, []byte(fmt.Sprintf(`{
 "log":{"disabled":true},
 "outbounds":[{"type":"direct","tag":"d"}],
 "providers":[{"type":"remote","tag":"r","url":%q}],
 "route":{"rules":[{"outbound":%q}]}
 }`, server.URL, testCase.target)))
				require.NoError(t, err)
				instance, err := box.New(box.Options{Context: ctx, Options: options})
				require.NoError(t, err)
				defer instance.Close()
				err = instance.PreStart()
				if testCase.expectErr != "" {
					require.ErrorContains(t, err, testCase.expectErr)
					return
				}
				require.NoError(t, err)
			})
		}
	})
}
