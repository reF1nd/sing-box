package box_test

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common/json"
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
