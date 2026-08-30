//go:build with_ebpf && (linux || android)

package ebpf

import (
	"errors"
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
