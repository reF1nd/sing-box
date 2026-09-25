package local

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/service/resolved"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/control"
	"github.com/sagernet/sing/common/json/badoption"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/common/x/list"
	"github.com/sagernet/sing/service"

	"github.com/godbus/dbus/v5"
	mDNS "github.com/miekg/dns"
)

func TestResolvedUnavailableErrors(t *testing.T) {
	for _, name := range []string{"UnknownMethod", "UnknownInterface", "ServiceUnknown", "NameHasNoOwner", "Spawn.ServiceNotFound", "AccessDenied", "NoReply", "Timeout", "UnknownProperty"} {
		want := name == "UnknownMethod" || name == "UnknownInterface" || name == "ServiceUnknown" || name == "NameHasNoOwner" || name == "Spawn.ServiceNotFound"
		value := dbus.Error{Name: "org.freedesktop.DBus.Error." + name, Body: []any{"test"}}
		for _, err := range []error{value, &value, fmt.Errorf("wrapped: %w", value), fmt.Errorf("wrapped: %w", &value)} {
			if got := isResolvedUnavailableError(err); got != want {
				t.Errorf("%s: %v, want %v", name, got, want)
			}
		}
	}
	for _, err := range []error{nil, context.Canceled, context.DeadlineExceeded, errors.New("Unknown / invalid method 'GetLink'"), errors.New("link has no DNS servers configured")} {
		if isResolvedUnavailableError(err) {
			t.Errorf("unexpected fallback for %v", err)
		}
	}
}

type resolvedTestMonitor struct{ tun.DefaultInterfaceMonitor }

func (*resolvedTestMonitor) DefaultInterface() *control.Interface {
	return &control.Interface{Index: 1, Name: "lo"}
}

func (*resolvedTestMonitor) RegisterCallback(tun.DefaultInterfaceUpdateCallback) *list.Element[tun.DefaultInterfaceUpdateCallback] {
	return nil
}

type resolvedTestNetwork struct{ adapter.NetworkManager }

func (*resolvedTestNetwork) AutoDetectInterface() bool              { return false }
func (*resolvedTestNetwork) DefaultOptions() adapter.NetworkOptions { return adapter.NetworkOptions{} }

func (*resolvedTestNetwork) InterfaceFinder() control.InterfaceFinder {
	return control.NewDefaultInterfaceFinder()
}
func (*resolvedTestNetwork) AutoRedirectOutputMarkFunc() control.Func { return nil }

type resolvedTestManager struct {
	incompatible atomic.Bool
	calls        atomic.Int32
}

func (m *resolvedTestManager) GetLink(_ int32) (dbus.ObjectPath, *dbus.Error) {
	m.calls.Add(1)
	if m.incompatible.Load() {
		return "", dbus.NewError("org.freedesktop.DBus.Error.UnknownMethod", []any{"Unknown / invalid method 'GetLink'"})
	}
	return "/org/freedesktop/resolve1/link/_1", nil
}

type resolvedTestProperties struct{ address M.Socksaddr }

func (p *resolvedTestProperties) Get(_ string, name string) (dbus.Variant, *dbus.Error) {
	switch name {
	case "DNSOverTLS":
		return dbus.MakeVariant("no"), nil
	case "DNSEx":
		return dbus.MakeVariant([]resolved.LinkDNSEx{{Family: 2, Address: p.address.Addr.AsSlice(), Port: p.address.Port}}), nil
	case "DNS":
		return dbus.MakeVariant([]resolved.LinkDNS{}), nil
	}
	return dbus.Variant{}, dbus.NewError("org.freedesktop.DBus.Error.UnknownProperty", nil)
}

func resolvedTestBus(t *testing.T) string {
	t.Helper()
	binary, err := exec.LookPath("dbus-daemon")
	if err != nil {
		t.Skip("dbus-daemon is required for private-bus integration")
	}
	cmd := exec.Command(binary, "--session", "--nofork", "--print-address=1")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		t.Fatal("missing private bus address")
	}
	return scanner.Text()
}

func resolvedTestWait(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("resolved state transition timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestResolvedFallbackPrivateBusRecovery(t *testing.T) {
	address := resolvedTestBus(t)
	provider, err := dbus.Connect(address)
	if err != nil {
		t.Fatal(err)
	}
	defer provider.Close()
	manager := new(resolvedTestManager)
	manager.incompatible.Store(true)
	if err = provider.Export(manager, "/org/freedesktop/resolve1", "org.freedesktop.resolve1.Manager"); err != nil {
		t.Fatal(err)
	}
	destination, _ := fallbackTestServer(t)
	if err = provider.Export(&resolvedTestProperties{destination}, "/org/freedesktop/resolve1/link/_1", "org.freedesktop.DBus.Properties"); err != nil {
		t.Fatal(err)
	}
	if _, err = provider.RequestName("org.freedesktop.resolve1", dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	client, err := dbus.Connect(address)
	if err != nil {
		t.Fatal(err)
	}
	ctx := service.ContextWith[adapter.NetworkManager](context.Background(), &resolvedTestNetwork{})
	resolver := &DBusResolvedResolver{ctx: ctx, logger: log.NewNOPFactory().Logger(), interfaceMonitor: &resolvedTestMonitor{}, systemBus: client}
	if err = resolver.Start(); err != nil {
		t.Fatal(err)
	}
	transport := fallbackTestTransport(t, resolver, destination)
	if !resolver.Fallback() {
		t.Fatal("missing GetLink did not enable fallback")
	}
	before := transport.Environment()
	probeCalls := manager.calls.Load()
	for range 10 {
		query := new(mDNS.Msg).SetQuestion("fallback.example.", mDNS.TypeA)
		if _, err = transport.Exchange(context.Background(), query); err != nil {
			t.Fatal(err)
		}
	}
	if manager.calls.Load() != probeCalls {
		t.Fatal("incompatible GetLink was called for every query")
	}
	manager.incompatible.Store(false)
	if _, err = provider.ReleaseName("org.freedesktop.resolve1"); err != nil {
		t.Fatal(err)
	}
	if _, err = provider.RequestName("org.freedesktop.resolve1", dbus.NameFlagDoNotQueue); err != nil {
		t.Fatal(err)
	}
	resolvedTestWait(t, func() bool { return !resolver.Fallback() && len(resolver.Environment()) > 0 })
	if slices.Equal(before, transport.Environment()) {
		t.Fatal("cache environment did not change on recovery")
	}
	query := new(mDNS.Msg).SetQuestion("recovered.example.", mDNS.TypeAAAA)
	response, err := transport.Exchange(context.Background(), query)
	if err != nil || len(response.Answer) != 1 {
		t.Fatalf("recovered response=%v error=%v", response, err)
	}
	if _, err = provider.ReleaseName("org.freedesktop.resolve1"); err != nil {
		t.Fatal(err)
	}
	resolvedTestWait(t, resolver.Fallback)
	if _, err = transport.Exchange(context.Background(), query); err != nil {
		t.Fatal(err)
	}
	if err = resolver.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err = resolver.Exchange(context.Background(), query); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("query after close: %v", err)
	}
}

type resolvedTestServices struct {
	adapter.ServiceManager
	services []adapter.Service
}

func (m *resolvedTestServices) Services() []adapter.Service { return m.services }
func TestResolvedFallbackRejectsOwnListener(t *testing.T) {
	for _, bind := range []string{"127.0.0.53", "0.0.0.0", "::"} {
		t.Run(bind, func(t *testing.T) {
			instance, err := resolved.NewService(context.Background(), log.NewNOPFactory().Logger(), "self", option.ResolvedServiceOptions{ListenOptions: option.ListenOptions{Listen: common.Ptr(badoption.Addr(netip.MustParseAddr(bind))), ListenPort: 53}})
			if err != nil {
				t.Fatal(err)
			}
			ctx := service.ContextWith[adapter.ServiceManager](context.Background(), &resolvedTestServices{services: []adapter.Service{instance}})
			local := M.SocksaddrFrom(netip.MustParseAddr("127.0.0.53"), 53)
			if err = checkResolvedFallback(ctx, []M.Socksaddr{local}); err == nil {
				t.Fatal("own listener was allowed")
			}
			if err = checkResolvedFallback(context.Background(), []M.Socksaddr{local}); err != nil {
				t.Fatalf("another instance's listener was rejected: %v", err)
			}
			local.Port = 6450
			if err = checkResolvedFallback(ctx, []M.Socksaddr{local}); err != nil {
				t.Fatal(err)
			}
		})
	}
}
