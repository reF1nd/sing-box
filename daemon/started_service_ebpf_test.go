package daemon

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/log"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/emptypb"
)

type testEBPFInbound struct {
	tag         string
	diagnostics adapter.EBPFRuntimeDiagnostics
	runtime     adapter.EBPFKernelRuntimeDiagnostics
}

func (i *testEBPFInbound) Start(adapter.StartStage) error { return nil }
func (i *testEBPFInbound) Close() error                   { return nil }
func (i *testEBPFInbound) Type() string                   { return "ebpf" }
func (i *testEBPFInbound) Tag() string                    { return i.tag }
func (i *testEBPFInbound) EBPFDiagnostics() adapter.EBPFRuntimeDiagnostics {
	return i.diagnostics
}

func (i *testEBPFInbound) EBPFKernelRuntime() adapter.EBPFKernelRuntimeDiagnostics {
	return i.runtime
}

type testPlainInbound struct{ tag string }

func (i *testPlainInbound) Start(adapter.StartStage) error { return nil }
func (i *testPlainInbound) Close() error                   { return nil }
func (i *testPlainInbound) Type() string                   { return "direct" }
func (i *testPlainInbound) Tag() string                    { return i.tag }

type testInboundManager struct {
	inbounds []adapter.Inbound
}

func (m *testInboundManager) Start(adapter.StartStage) error { return nil }
func (m *testInboundManager) Close() error                   { return nil }
func (m *testInboundManager) Inbounds() []adapter.Inbound    { return m.inbounds }
func (m *testInboundManager) Get(tag string) (adapter.Inbound, bool) {
	for _, inbound := range m.inbounds {
		if inbound.Tag() == tag {
			return inbound, true
		}
	}
	return nil, false
}
func (m *testInboundManager) Remove(string) error { return nil }
func (m *testInboundManager) Create(
	context.Context,
	adapter.Router,
	log.ContextLogger,
	string,
	string,
	any,
) error {
	return nil
}

func TestGetEBPFDiagnosticsUsesSingBoxAPI(t *testing.T) {
	if APIVersion < 6 {
		t.Fatalf("eBPF diagnostics requires API version 6, got %d", APIVersion)
	}
	observedAt := time.UnixMilli(1700000000123)
	lastErrorAt := observedAt.Add(time.Second)
	manager := &testInboundManager{inbounds: []adapter.Inbound{
		&testPlainInbound{tag: "direct-in"},
		&testEBPFInbound{tag: "ebpf-in", diagnostics: adapter.EBPFRuntimeDiagnostics{
			SchemaVersion: adapter.EBPFDiagnosticsSchemaVersion,
			ObservedAt:    observedAt,
			Tag:           "ebpf-in",
			State:         "recovering",
			LocalEnabled:  true,
			LastError:     "attachment missing",
			LastErrorAt:   &lastErrorAt,
			Attachments: []adapter.EBPFAttachmentDiagnostics{{
				InterfaceName:  "wlan0",
				InterfaceIndex: 7,
				Role:           "local",
				Mechanism:      "tcx",
			}},
			LocalBypassRuleSet: adapter.EBPFBypassRuleSetDiagnostics{
				Consistent: true,
				BackendState: map[string]adapter.EBPFBypassRuleSetBackendState{
					"TC": {Version: 3, Known: true},
				},
			},
			Counters: adapter.EBPFCounters{TCSharedFragmentPasses: 9},
			UDPNAT: adapter.EBPFUDPNATDiagnostics{
				ActiveSessions:           3,
				CreatedSessions:          7,
				CapacityEvictions:        1,
				QueueDrops:               2,
				SocketReleaseEvents:      5,
				SocketReleaseMatched:     4,
				ReleaseNotificationDrops: 1,
			},
		}, runtime: adapter.EBPFKernelRuntimeDiagnostics{
			ObservedAt: observedAt,
			Programs: []adapter.EBPFProgramDiagnostics{{
				ID: 42, Name: "sb_ebpf_conn4", Type: "CGroupSockAddr", MapCount: 2, MapIDs: []uint32{7, 8},
			}},
			MapOccupancy: adapter.EBPFMapOccupancyDiagnostics{
				Status: "pass",
				Maps: []adapter.EBPFMapDiagnostics{{
					ID: 7, Name: "sb_tcp_redirect", Type: "LRUHash", MaxEntries: 4096, Entries: 3, Supported: true,
				}},
			},
		}},
	}}
	service := &StartedService{
		serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED},
		instance:      &Instance{inboundManager: manager},
	}
	response, err := service.GetEBPFDiagnostics(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != adapter.EBPFDiagnosticsSchemaVersion {
		t.Fatalf("schema version = %d, want %d", response.SchemaVersion, adapter.EBPFDiagnosticsSchemaVersion)
	}
	if len(response.Inbounds) != 1 {
		t.Fatalf("inbounds = %d, want one eBPF provider", len(response.Inbounds))
	}
	diagnostics := response.Inbounds[0]
	if diagnostics.Tag != "ebpf-in" || diagnostics.ObservedAt != observedAt.UnixMilli() {
		t.Fatalf("unexpected diagnostics identity: %+v", diagnostics)
	}
	if diagnostics.LastErrorAt == nil || *diagnostics.LastErrorAt != lastErrorAt.UnixMilli() {
		t.Fatalf("last error timestamp = %v, want %d", diagnostics.LastErrorAt, lastErrorAt.UnixMilli())
	}
	if len(diagnostics.Attachments) != 1 || diagnostics.Attachments[0].InterfaceIndex != 7 {
		t.Fatalf("attachments = %+v", diagnostics.Attachments)
	}
	if state := diagnostics.LocalBypassRuleSet.BackendState["TC"]; state == nil || !state.Known || state.Version != 3 {
		t.Fatalf("backend state = %+v", state)
	}
	if diagnostics.Counters == nil || diagnostics.Counters.TcSharedFragmentPasses != 9 {
		t.Fatalf("counters = %+v", diagnostics.Counters)
	}
	if diagnostics.UdpNAT == nil || diagnostics.UdpNAT.ActiveSessions != 3 ||
		diagnostics.UdpNAT.CreatedSessions != 7 || diagnostics.UdpNAT.ReleaseNotificationDrops != 1 {
		t.Fatalf("UDP NAT diagnostics = %+v", diagnostics.UdpNAT)
	}
	if response.KernelRuntime == nil || len(response.KernelRuntime.Programs) != 1 ||
		response.KernelRuntime.Programs[0].Id != 42 || response.KernelRuntime.MapOccupancy == nil ||
		len(response.KernelRuntime.MapOccupancy.Maps) != 1 || response.KernelRuntime.MapOccupancy.Maps[0].Entries != 3 {
		t.Fatalf("kernel runtime = %+v", response.KernelRuntime)
	}
}

func TestGetEBPFDiagnosticsReturnsSchemaVersionWithoutInbound(t *testing.T) {
	service := &StartedService{
		serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED},
		instance:      &Instance{inboundManager: &testInboundManager{}},
	}
	response, err := service.GetEBPFDiagnostics(context.Background(), &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != adapter.EBPFDiagnosticsSchemaVersion {
		t.Fatalf("schema version = %d, want %d", response.SchemaVersion, adapter.EBPFDiagnosticsSchemaVersion)
	}
	if len(response.Inbounds) != 0 {
		t.Fatalf("inbounds = %d, want none", len(response.Inbounds))
	}
}

func TestGetEBPFDiagnosticsGRPCRegistrationAndAuthentication(t *testing.T) {
	service := &StartedService{
		serviceStatus: &ServiceStatus{Status: ServiceStatus_STARTED},
		instance: &Instance{inboundManager: &testInboundManager{inbounds: []adapter.Inbound{
			&testEBPFInbound{tag: "ebpf-in", diagnostics: adapter.EBPFRuntimeDiagnostics{Tag: "ebpf-in"}},
		}}},
	}
	server := NewServer(service, "test-secret")
	listener := bufconn.Listen(1024 * 1024)
	go func() {
		_ = server.Serve(listener)
	}()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	connection, err := grpc.NewClient(
		"passthrough:///sing-box-api-test",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) {
			return listener.Dial()
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = connection.Close() })
	client := NewStartedServiceClient(connection)

	_, err = client.GetEBPFDiagnostics(context.Background(), &emptypb.Empty{})
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("unauthenticated call error = %v, want Unauthenticated", err)
	}
	authenticatedContext := metadata.AppendToOutgoingContext(
		context.Background(),
		"authorization",
		"Bearer test-secret",
	)
	response, err := client.GetEBPFDiagnostics(authenticatedContext, &emptypb.Empty{})
	if err != nil {
		t.Fatal(err)
	}
	if response.SchemaVersion != adapter.EBPFDiagnosticsSchemaVersion {
		t.Fatalf("RPC schema version = %d, want %d", response.SchemaVersion, adapter.EBPFDiagnosticsSchemaVersion)
	}
	if len(response.Inbounds) != 1 || response.Inbounds[0].Tag != "ebpf-in" {
		t.Fatalf("unexpected RPC response: %+v", response.Inbounds)
	}
}
