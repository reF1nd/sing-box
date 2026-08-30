//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"testing"

	CiliumEBPF "github.com/cilium/ebpf"
	commonEBPF "github.com/sagernet/sing-box/common/ebpf"
	"golang.org/x/sys/unix"
)

func TestTCXUnsupportedError(t *testing.T) {
	if !tcxUnsupportedError(CiliumEBPF.ErrNotSupported) ||
		!tcxUnsupportedError(errors.Join(errors.New("attach"), unix.EOPNOTSUPP)) ||
		!tcxUnsupportedError(unix.ENOSYS) {
		t.Fatal("expected unsupported TCX errors to be classified")
	}
	if tcxUnsupportedError(unix.EPERM) || tcxUnsupportedError(unix.EINVAL) {
		t.Fatal("permission and interface-specific errors must not disable TCX globally")
	}
}

func TestTCVethNamesFitLinuxLimit(t *testing.T) {
	redirectName, deliveryName, err := nextTCVethNames()
	if err != nil {
		t.Fatal(err)
	}
	if len(redirectName) > 15 || len(deliveryName) > 15 {
		t.Fatalf("delivery link names exceed Linux limit: %q %q", redirectName, deliveryName)
	}
	if redirectName == deliveryName {
		t.Fatal("delivery link names are identical")
	}
}

func TestRetainLocalAttachmentStatesDuringHandoff(t *testing.T) {
	desired := map[string]tcAttachmentState{
		"wlan2": {
			index:   2,
			framing: commonEBPF.TCLinkFramingEthernet,
			role:    tcInterfaceRole{shared: true},
		},
	}
	attachments := []*tcInterfaceAttachment{
		{
			interfaceName:  "rmnet_data1",
			interfaceIndex: 19,
			framing:        commonEBPF.TCLinkFramingRawIP,
			role:           tcInterfaceRole{local: true},
		},
	}

	retainLocalAttachmentStates("", desired, attachments)

	state, loaded := desired["rmnet_data1"]
	if !loaded {
		t.Fatal("local attachment was not retained while default interface was unavailable")
	}
	if state.index != 19 || state.framing != commonEBPF.TCLinkFramingRawIP || !state.role.local {
		t.Fatalf("unexpected retained local state: %+v", state)
	}
	if _, loaded = desired["wlan2"]; !loaded {
		t.Fatal("shared attachment was dropped while retaining local attachment")
	}
}

func TestRetainLocalAttachmentStatesDoesNotOverrideNewDefault(t *testing.T) {
	desired := map[string]tcAttachmentState{
		"rmnet_data2": {
			index:   20,
			framing: commonEBPF.TCLinkFramingRawIP,
			role:    tcInterfaceRole{local: true},
		},
	}
	attachments := []*tcInterfaceAttachment{
		{
			interfaceName:  "rmnet_data1",
			interfaceIndex: 19,
			framing:        commonEBPF.TCLinkFramingRawIP,
			role:           tcInterfaceRole{local: true},
		},
	}

	retainLocalAttachmentStates("rmnet_data2", desired, attachments)

	if _, loaded := desired["rmnet_data1"]; loaded {
		t.Fatal("stale local attachment was retained after a new default interface appeared")
	}
}

func TestHandoffTCGlobalSysctls(t *testing.T) {
	previous := &tcDeliveryLink{
		globalSysctls: []tcSysctlState{{path: "all/rp_filter", original: "1"}},
	}
	next := &tcDeliveryLink{}
	handoffTCGlobalSysctls(previous, next)
	if len(previous.globalSysctls) != 0 {
		t.Fatal("previous delivery retained global sysctl ownership")
	}
	if len(next.globalSysctls) != 1 || next.globalSysctls[0].path != "all/rp_filter" {
		t.Fatalf("new delivery did not receive global sysctl ownership: %+v", next.globalSysctls)
	}
}

func TestHandoffTCGlobalSysctlsKeepsFreshState(t *testing.T) {
	previous := &tcDeliveryLink{
		globalSysctls: []tcSysctlState{{path: "all/rp_filter", original: "1"}},
	}
	next := &tcDeliveryLink{
		globalSysctls: []tcSysctlState{{path: "all/rp_filter", original: "2"}},
	}
	handoffTCGlobalSysctls(previous, next)
	if len(previous.globalSysctls) != 0 {
		t.Fatal("previous delivery retained global sysctl ownership")
	}
	if len(next.globalSysctls) != 1 || next.globalSysctls[0].original != "2" {
		t.Fatalf("new delivery state was unexpectedly replaced: %+v", next.globalSysctls)
	}
}

func TestRestoreTCSysctlStatesPreservesExternalChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "rp_filter")
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	state, changed, err := setTCSysctl(path, "0")
	if err != nil || !changed {
		t.Fatalf("set sysctl: changed=%v err=%v", changed, err)
	}
	if err = restoreTCSysctlStates([]tcSysctlState{state}); err != nil {
		t.Fatal(err)
	}
	value, err := os.ReadFile(path)
	if err != nil || string(value) != "1" {
		t.Fatalf("sysctl was not restored: value=%q err=%v", value, err)
	}

	state, changed, err = setTCSysctl(path, "0")
	if err != nil || !changed {
		t.Fatalf("set sysctl for external change: changed=%v err=%v", changed, err)
	}
	if err = os.WriteFile(path, []byte("2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err = restoreTCSysctlStates([]tcSysctlState{state}); err != nil {
		t.Fatal(err)
	}
	value, err = os.ReadFile(path)
	if err != nil || string(value) != "2\n" {
		t.Fatalf("external sysctl change was overwritten: value=%q err=%v", value, err)
	}
}

func TestTransitionTCXInterfaceRoleAttachesBeforeDetach(t *testing.T) {
	var events []string
	err := transitionTCXInterfaceRole(
		tcInterfaceRole{local: true},
		tcInterfaceRole{shared: true},
		true,
		false,
		func(local bool) error {
			if local {
				events = append(events, "attach-local")
			} else {
				events = append(events, "attach-shared")
			}
			return nil
		},
		func(local bool) error {
			if local {
				events = append(events, "detach-local")
			} else {
				events = append(events, "detach-shared")
			}
			return nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"attach-shared", "detach-local"}
	if !slices.Equal(events, want) {
		t.Fatalf("unexpected TCX transition order: got %v, want %v", events, want)
	}
}

func TestTransitionTCXInterfaceRoleRollsBackNewLinks(t *testing.T) {
	var events []string
	err := transitionTCXInterfaceRole(
		tcInterfaceRole{},
		tcInterfaceRole{local: true, shared: true},
		false,
		false,
		func(local bool) error {
			if local {
				events = append(events, "attach-local")
				return nil
			}
			events = append(events, "attach-shared")
			return errors.New("shared attach failed")
		},
		func(local bool) error {
			if local {
				events = append(events, "detach-local")
			} else {
				events = append(events, "detach-shared")
			}
			return nil
		},
	)
	if err == nil {
		t.Fatal("expected TCX transition failure")
	}
	want := []string{"attach-local", "attach-shared", "detach-local"}
	if !slices.Equal(events, want) {
		t.Fatalf("unexpected TCX rollback order: got %v, want %v", events, want)
	}
}
