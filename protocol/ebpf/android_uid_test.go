//go:build with_ebpf && (linux || android)

package ebpf

import (
	"math"
	"testing"

	"github.com/sagernet/sing-box/adapter"
	ECommon "github.com/sagernet/sing-box/common/ebpf"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-tun"
)

func TestValidateAndroidUIDOptions(t *testing.T) {
	androidOptions := option.EBPFLocalOptions{
		IncludeAndroidUser: []int{0, 10},
		IncludePackage:     []string{"com.example.include"},
		ExcludePackage:     []string{"com.example.exclude"},
	}
	if err := validateAndroidUIDOptions("android", androidOptions); err != nil {
		t.Fatal(err)
	}
	if err := validateAndroidUIDOptions("linux", androidOptions); err == nil {
		t.Fatal("expected Android UID options to be rejected on Linux")
	}
	androidOptions.IncludeAndroidUser = []int{-1}
	if err := validateAndroidUIDOptions("android", androidOptions); err == nil {
		t.Fatal("expected a negative Android user ID to be rejected")
	}
	androidOptions.IncludeAndroidUser = []int{42949}
	if err := validateAndroidUIDOptions("android", androidOptions); err == nil {
		t.Fatal("expected an overflowing Android user ID to be rejected")
	}
}

func TestResolveAndroidUIDPolicy(t *testing.T) {
	packageManager := &testPackageManager{
		idByPackage: map[string]uint32{
			"com.example.include": 10001,
			"com.example.shared":  10002,
			"com.example.peer":    10002,
			"com.example.exclude": 10003,
		},
		packagesByID: map[uint32][]string{
			10001: {"com.example.include"},
			10002: {"com.example.shared", "com.example.peer"},
			10003: {"com.example.exclude"},
		},
	}
	inbound := &Inbound{
		logger: log.NewNOPFactory().Logger(),
		networkManager: &testNetworkManager{
			packageManager: packageManager,
		},
		androidUIDOptions: &androidUIDOptions{
			includeAndroidUser: []int{0, 10},
			includePackage:     []string{"com.example.include", "com.example.shared"},
			excludePackage:     []string{"com.example.exclude"},
		},
		cgroupPolicy: ECommon.CgroupPolicy{
			IncludeUID: []ECommon.UIDRange{{Start: 2000, End: 2000}},
			ExcludeUID: []ECommon.UIDRange{{Start: 3000, End: 3000}},
		},
	}
	if err := inbound.resolveAndroidUIDPolicy(); err != nil {
		t.Fatal(err)
	}
	for _, uid := range []uint32{2000, 10001, 10002, 1010001, 1010002} {
		if !uidInRanges(uid, inbound.cgroupPolicy.IncludeUID) {
			t.Fatalf("expected UID %d in include policy: %+v", uid, inbound.cgroupPolicy.IncludeUID)
		}
	}
	for _, uid := range []uint32{3000, 10003, 1010003, 500000, 1100000} {
		if !uidInRanges(uid, inbound.cgroupPolicy.ExcludeUID) {
			t.Fatalf("expected UID %d in exclude policy: %+v", uid, inbound.cgroupPolicy.ExcludeUID)
		}
	}
	for _, uid := range []uint32{10001, 1010001} {
		if uidInRanges(uid, inbound.cgroupPolicy.ExcludeUID) {
			t.Fatalf("included package UID %d was unexpectedly excluded", uid)
		}
	}
}

func TestResolveAndroidUIDPolicyRequiresPackageManager(t *testing.T) {
	inbound := &Inbound{
		logger:            log.NewNOPFactory().Logger(),
		networkManager:    &testNetworkManager{},
		androidUIDOptions: &androidUIDOptions{includePackage: []string{"com.example.include"}},
	}
	if err := inbound.resolveAndroidUIDPolicy(); err == nil {
		t.Fatal("expected a missing package manager to be rejected")
	}
}

func TestFormatUIDRanges(t *testing.T) {
	formatted := formatUIDRanges([]ECommon.UIDRange{
		{Start: 1000, End: 1000},
		{Start: 2000, End: 2999},
		{Start: math.MaxUint32, End: math.MaxUint32},
	})
	if formatted != "1000, 2000:2999, 4294967295" {
		t.Fatalf("unexpected formatted UID ranges: %s", formatted)
	}
	if formatted = formatUIDRanges(nil); formatted != "" {
		t.Fatalf("unexpected empty UID ranges: %s", formatted)
	}
}

func uidInRanges(uid uint32, uidRanges []ECommon.UIDRange) bool {
	for _, uidRange := range uidRanges {
		if uid >= uidRange.Start && uid <= uidRange.End {
			return true
		}
	}
	return false
}

type testNetworkManager struct {
	adapter.NetworkManager
	packageManager tun.PackageManager
}

func (m *testNetworkManager) PackageManager() tun.PackageManager {
	return m.packageManager
}

type testPackageManager struct {
	idByPackage     map[string]uint32
	idByShared      map[string]uint32
	packagesByID    map[uint32][]string
	sharedPackageID map[uint32]string
}

func (m *testPackageManager) Start() error { return nil }
func (m *testPackageManager) Close() error { return nil }

func (m *testPackageManager) IDByPackage(packageName string) (uint32, bool) {
	uid, loaded := m.idByPackage[packageName]
	return uid, loaded
}

func (m *testPackageManager) IDBySharedPackage(packageName string) (uint32, bool) {
	uid, loaded := m.idByShared[packageName]
	return uid, loaded
}

func (m *testPackageManager) PackageByID(uid uint32) (string, bool) {
	packages, loaded := m.packagesByID[uid]
	if !loaded || len(packages) == 0 {
		return "", false
	}
	return packages[0], true
}

func (m *testPackageManager) PackagesByID(uid uint32) ([]string, bool) {
	packages, loaded := m.packagesByID[uid]
	return packages, loaded
}

func (m *testPackageManager) SharedPackageByID(uid uint32) (string, bool) {
	packageName, loaded := m.sharedPackageID[uid]
	return packageName, loaded
}
