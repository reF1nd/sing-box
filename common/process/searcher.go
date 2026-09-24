package process

import (
	"context"
	"net/netip"
	"os/user"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-tun"
	"github.com/sagernet/sing/common"
	E "github.com/sagernet/sing/common/exceptions"
	F "github.com/sagernet/sing/common/format"
)

type Searcher interface {
	FindProcessInfo(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*adapter.ConnectionOwner, error)
	ResetCache()
	Close() error
}

// LookupMode controls whether executable paths are required or best effort.
type LookupMode uint8

const (
	LookupFull LookupMode = iota
	// LookupOwner preserves UID/package attribution and only uses cached paths
	// for applications. Native processes receive a budgeted path lookup.
	LookupOwner
)

type ModeSearcher interface {
	FindProcessInfoMode(ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort, mode LookupMode) (*adapter.ConnectionOwner, error)
}

var ErrNotFound = E.New("process not found")

type Config struct {
	Logger         log.ContextLogger
	PackageManager tun.PackageManager
}

func FindProcessInfo(searcher Searcher, ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort) (*adapter.ConnectionOwner, error) {
	return FindProcessInfoMode(searcher, ctx, network, source, destination, LookupFull)
}

func FindProcessInfoMode(searcher Searcher, ctx context.Context, network string, source netip.AddrPort, destination netip.AddrPort, mode LookupMode) (*adapter.ConnectionOwner, error) {
	var info *adapter.ConnectionOwner
	var err error
	if modeSearcher, ok := searcher.(ModeSearcher); ok {
		info, err = modeSearcher.FindProcessInfoMode(ctx, network, source, destination, mode)
	} else {
		info, err = searcher.FindProcessInfo(ctx, network, source, destination)
	}
	if err != nil {
		return nil, err
	}
	completeProcessInfo(info, nil)
	return info, nil
}

func completeProcessInfo(info *adapter.ConnectionOwner, packageManager tun.PackageManager) {
	if info.UserId != -1 && info.UserName == "" {
		osUser, _ := user.LookupId(F.ToString(info.UserId))
		if osUser != nil {
			info.UserName = osUser.Username
		}
	}
	if packageManager == nil || info.UserId == -1 {
		return
	}
	appID := uint32(info.UserId) % 100000
	var packageNames []string
	if sharedPackage, loaded := packageManager.SharedPackageByID(appID); loaded {
		packageNames = append(packageNames, sharedPackage)
	}
	if packages, loaded := packageManager.PackagesByID(appID); loaded {
		packageNames = append(packageNames, packages...)
	}
	info.PackageNames = common.Uniq(packageNames)
}
