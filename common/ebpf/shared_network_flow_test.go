//go:build with_ebpf && (linux || android)

package ebpf

import (
	"testing"
	"time"
)

func TestSharedNetworkFlowReferences(t *testing.T) {
	backend := new(SharedNetworkBackend)
	flow := SharedNetworkFlowHandle{
		originalKey: sharedNetworkOriginalKey{InterfaceIndex: 7, Protocol: ProtocolTCP},
		listenerKey: sharedNetworkListenerKey{Protocol: ProtocolTCP, ListenerPort: 1234},
		generation:  11,
	}
	backend.retainFlowLocked(flow)
	backend.retainFlowLocked(flow)
	if backend.releaseFlowReferenceLocked(flow) {
		t.Fatal("first release removed a multiply referenced flow")
	}
	if references := backend.flowReferences[flow]; references != 1 {
		t.Fatalf("unexpected remaining flow references: %d", references)
	}
	if !backend.releaseFlowReferenceLocked(flow) {
		t.Fatal("last release did not select the flow for cleanup")
	}
	if _, loaded := backend.flowReferences[flow]; loaded {
		t.Fatal("released flow reference was retained")
	}
	if backend.releaseFlowReferenceLocked(flow) {
		t.Fatal("duplicate release selected an already released flow for cleanup")
	}
}

func TestSharedNetworkTCPReleaseGrace(t *testing.T) {
	backend := new(SharedNetworkBackend)
	flow := SharedNetworkFlowHandle{
		originalKey: sharedNetworkOriginalKey{InterfaceIndex: 7, Protocol: ProtocolTCP},
		listenerKey: sharedNetworkListenerKey{Protocol: ProtocolTCP, ListenerPort: 1234},
		generation:  11,
	}
	backend.retainFlowLocked(flow)
	if !backend.releaseFlowReferenceLocked(flow) {
		t.Fatal("last release did not select TCP flow for grace period")
	}
	backend.deferTCPFlowReleaseLocked(flow, time.Now())
	backend.retainFlowLocked(flow)
	if _, loaded := backend.flowReleases[flow]; loaded {
		t.Fatal("retained TCP flow remained pending for release")
	}
}
