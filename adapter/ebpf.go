package adapter

import "time"

// EBPFDiagnosticsSchemaVersion versions the complete GetEBPFDiagnostics
// response. It remains available even when no eBPF inbound is running.
const EBPFDiagnosticsSchemaVersion = 7

// EBPFDiagnosticsProvider exposes a running inbound's eBPF state to the
// sing-box API without coupling the API service to the optional eBPF package.
type EBPFDiagnosticsProvider interface {
	EBPFDiagnostics() EBPFRuntimeDiagnostics
	EBPFKernelRuntime() EBPFKernelRuntimeDiagnostics
}

type EBPFKernelRuntimeDiagnostics struct {
	ObservedAt    time.Time
	Programs      []EBPFProgramDiagnostics
	ProgramsError string
	MapOccupancy  EBPFMapOccupancyDiagnostics
}

type EBPFProgramDiagnostics struct {
	ID       uint32
	Name     string
	Type     string
	MapCount int
	MapIDs   []uint32
}

type EBPFMapOccupancyDiagnostics struct {
	Status string
	Maps   []EBPFMapDiagnostics
	Error  string
}

type EBPFMapDiagnostics struct {
	ID         uint32
	Name       string
	Type       string
	MaxEntries uint32
	KeySize    uint32
	ValueSize  uint32
	Flags      uint32
	Entries    uint32
	Supported  bool
	Error      string
}

type EBPFRuntimeDiagnostics struct {
	SchemaVersion int
	ObservedAt    time.Time
	Tag           string
	State         string

	LocalEnabled                 bool
	LocalDataPlane               string
	LocalCgroupAttachMode        string
	LocalUDPCleanupMode          string
	LocalUDPUserspaceCleanupMode string
	LocalUDPStorageMode          string
	LocalUDPTimeMode             string
	SharedEnabled                bool
	SharedDataPlane              string
	FakeIPICMPReply              bool
	TCBackendMode                string
	TCListenerLookupMode         string
	TCAttachmentMode             string
	TCDeliveryInterface          string
	TCDeliveryInterfaceIndex     int
	TCRoutingMark                uint32
	TCRoutingTable               int
	TCRoutingPriority            int
	TCAttachmentCount            int
	TCRetiredAttachmentCount     int
	TCRetiredDeliveryCount       int
	TCRequiresRebuild            bool
	TCHealthStatus               string
	TCLastHealthCheckAt          *time.Time
	TCLastReconcileAt            *time.Time
	TCNetworkGeneration          uint64

	Attachments []EBPFAttachmentDiagnostics

	LastError             string
	LastErrorAt           *time.Time
	LastRecoveryAt        *time.Time
	RecoveryPending       bool
	RecoveryUnrecoverable bool
	NextRetryAt           *time.Time

	LocalBypassRuleSet  EBPFBypassRuleSetDiagnostics
	SharedBypassRuleSet EBPFBypassRuleSetDiagnostics

	UDPSessionCount int
	UDPNAT          EBPFUDPNATDiagnostics
	UDPReplySockets EBPFUDPReplySocketDiagnostics
	Counters        EBPFCounters
}

type EBPFBypassRuleSetDiagnostics struct {
	Consistent            bool
	Pending               bool
	PolicyVersion         uint64
	ExpectedPolicyVersion uint64
	RetryCount            uint64
	BackendState          map[string]EBPFBypassRuleSetBackendState
}

type EBPFUDPNATDiagnostics struct {
	ActiveSessions                 int
	CreatedSessions                uint64
	CapacityEvictions              uint64
	QueueDrops                     uint64
	SocketReleaseEvents            uint64
	SocketReleaseMatched           uint64
	PendingReleaseCapacityRejected uint64
	ReleaseNotificationDrops       uint64
}

type EBPFAttachmentDiagnostics struct {
	InterfaceName  string
	InterfaceIndex int
	Role           string
	Framing        string
	Mechanism      string
	ICMPEchoReply  bool
}

type EBPFBypassRuleSetBackendState struct {
	Version uint64
	Known   bool
}

type EBPFUDPReplySocketDiagnostics struct {
	Count            int64
	Peak             int64
	Evicted          int64
	CapacityRejected int64
}

type EBPFCounters struct {
	AssignmentLookupFailures      uint64
	TCSocketLookupFailures        uint64
	TCSKAssignFailures            uint64
	TCAssignmentUpdateFailures    uint64
	TCLocalFragmentPasses         uint64
	TCSharedFragmentPasses        uint64
	TokenReservationFailures      uint64
	RewriteFailures               uint64
	SharedIngressFragmentPasses   uint64
	SharedEgressFragmentPasses    uint64
	SharedReconcileFailures       uint64
	RecoveryAttempts              uint64
	RecoverySuccesses             uint64
	RecoveryFailures              uint64
	FakeIPICMPReplies             uint64
	FakeIPICMPPassThrough         uint64
	FakeIPICMPRewriteFailureDrops uint64
}
