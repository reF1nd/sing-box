//go:build with_ebpf && (linux || android)

package ebpf

// uidRange and portRange are sing-box configuration-side ranges. They are
// deliberately kept out of sing-ebpf: the library receives only final
// UIDDecision and PortDecision actions, while parsing and selector semantics
// belong to this inbound.
type uidRange struct {
	Start uint32
	End   uint32
}

type portRange struct {
	Start uint16
	End   uint16
}

type localUIDPolicy struct {
	BypassPrivateAddress bool
	IncludeUIDConfigured bool
	IncludeUID           []uidRange
	ExcludeUID           []uidRange
}
