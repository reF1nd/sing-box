//go:build linux

package process

import (
	"context"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"

	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	M "github.com/sagernet/sing/common/metadata"

	"github.com/stretchr/testify/require"
)

func TestFindProcessInfoByPID(t *testing.T) {
	processInfo, err := FindProcessInfoByPID(uint32(os.Getpid()), uint32(os.Getuid()), nil)
	if err != nil {
		t.Fatal(err)
	}
	if processInfo.ProcessID != uint32(os.Getpid()) || processInfo.UserId != int32(os.Getuid()) {
		t.Fatalf("unexpected process identity: %+v", processInfo)
	}
	if len(processInfo.ProcessPaths) == 0 || processInfo.ProcessPaths[0] == "" {
		t.Fatal("missing process path")
	}
}

type testPackageManager struct {
	tun.PackageManager
	appID uint32
}

func (m testPackageManager) PackagesByID(id uint32) ([]string, bool) {
	if id == m.appID {
		return []string{"app.one", "app.two"}, true
	}
	return nil, false
}

func (m testPackageManager) SharedPackageByID(id uint32) (string, bool) {
	return "", false
}

func TestLookupOwnerSkipsProcForNewSockets(t *testing.T) {
	raw, err := NewSearcher(Config{
		Logger:         log.NewNOPFactory().NewLogger("test"),
		PackageManager: testPackageManager{appID: uint32(os.Getuid()) % 100000},
	})
	require.NoError(t, err)
	defer raw.Close()
	s := raw.(*linuxSearcher)
	var scans atomic.Int32
	s.processPathCache.build = func(ctx context.Context, uid uint32) (map[uint32][]string, error) {
		scans.Add(1)
		return buildProcessPaths(ctx, uid)
	}
	for range 8 {
		conn, listenErr := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		require.NoError(t, listenErr)
		defer conn.Close()
		source := M.AddrPortFromNet(conn.LocalAddr())
		info, lookupErr := FindProcessInfoMode(s, context.Background(), "udp", source, netip.AddrPort{}, LookupOwner)
		require.NoError(t, lookupErr)
		require.Equal(t, []string{"app.one", "app.two"}, info.PackageNames)
		require.Equal(t, int32(os.Getuid()), info.UserId)
		require.Empty(t, info.ProcessPaths)
	}
	require.Zero(t, scans.Load())
}

func TestLookupFullStillResolvesApplicationPath(t *testing.T) {
	raw, err := NewSearcher(Config{Logger: log.NewNOPFactory().NewLogger("test"), PackageManager: testPackageManager{appID: uint32(os.Getuid()) % 100000}})
	require.NoError(t, err)
	defer raw.Close()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	require.NoError(t, err)
	defer conn.Close()
	info, err := FindProcessInfoMode(raw, context.Background(), "udp", M.AddrPortFromNet(conn.LocalAddr()), netip.AddrPort{}, LookupFull)
	require.NoError(t, err)
	executable, err := os.Executable()
	require.NoError(t, err)
	require.Contains(t, info.ProcessPaths, executable)
	require.Equal(t, []string{"app.one", "app.two"}, info.PackageNames)
}
