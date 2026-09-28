package process

import (
	"slices"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-tun"
)

type processTestPackageManager struct {
	tun.PackageManager
	queriedIDs []uint32
}

func (m *processTestPackageManager) SharedPackageByID(id uint32) (string, bool) {
	m.queriedIDs = append(m.queriedIDs, id)
	return "shared.package", true
}

func (m *processTestPackageManager) PackagesByID(id uint32) ([]string, bool) {
	m.queriedIDs = append(m.queriedIDs, id)
	return []string{"shared.package", "client.package", "client.package"}, true
}

func TestCompleteProcessInfoAndroidMultiUser(t *testing.T) {
	manager := &processTestPackageManager{}
	info := &adapter.ConnectionOwner{ProcessID: 42, UserId: 1012345, UserName: "existing", ProcessPath: "/bin/client"}
	completeProcessInfo(info, manager)
	if !slices.Equal(manager.queriedIDs, []uint32{12345, 12345}) {
		t.Fatalf("package lookup did not use Android app ID: %v", manager.queriedIDs)
	}
	if !slices.Equal(info.AndroidPackageNames, []string{"shared.package", "client.package"}) {
		t.Fatalf("unexpected Android packages: %v", info.AndroidPackageNames)
	}
	if info.ProcessID != 42 || info.UserId != 1012345 || info.UserName != "existing" || info.ProcessPath != "/bin/client" {
		t.Fatalf("process identity changed: %+v", info)
	}
}

func TestCompleteProcessInfoUnknownUser(t *testing.T) {
	manager := &processTestPackageManager{}
	info := &adapter.ConnectionOwner{UserId: -1}
	completeProcessInfo(info, manager)
	if len(manager.queriedIDs) != 0 || len(info.AndroidPackageNames) != 0 {
		t.Fatalf("unknown user triggered package lookup: %+v", info)
	}
}
