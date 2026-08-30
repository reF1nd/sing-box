# eBPF TC backend

The eBPF inbound uses one TC object for local, shared, and hybrid operation.
Selected TCP and UDP packets retain their original address and port tuple and
enter the normal sing-box routing pipeline after socket assignment.

## Packet paths

Local traffic is selected at TC egress on the current default interface.
Forwarded packets are excluded through `ingress_ifindex`; sockets created by
sing-box are identified by their kernel socket cookie. An exclusive process
cgroup can populate and release the cookie map in kernel hooks. When the
cgroup is shared or cannot be attached, the default dialer and transparent
reply sockets register their own cookie once at creation time.
Selected packets are addressed to the delivery peer, cross the veth, and are assigned at
its ingress hook. L3-only links receive an Ethernet header before this redirect.

Shared traffic is selected and assigned at TC ingress on each configured
downstream interface. Hybrid mode installs both roles and keeps their policy and
IPv6 gates independent, including when one interface has both roles.

Local egress and shared ingress each have Ethernet and raw-IP program variants;
the selected variant follows the link encapsulation reported by netlink.
`classifier/delivery_ingress` always parses Ethernet from the internal veth.
Local and delivery use the local IPv6 flag; shared uses the shared IPv6 flag.
Both flags are static for the lifetime of the inbound.

Fragmented IPv4 datagrams and non-atomic IPv6 fragments bypass before policy
selection. IPv6 atomic fragments continue through extension-header parsing.

## Socket assignment

TCP listeners use a `SOCKMAP` on kernels that support the preferred listener
fallback. Established TCP lookup uses the original tuple before falling back to the
listener. If the SOCKMAP cannot be created or the modern program is rejected by the
kernel verifier, sing-box loads a legacy TCP section that does not reference the map
and performs direct `bpf_skc_lookup_tcp` lookup. UDP lookup substitutes only the
internal listener port. `tc_assignment` records the original tuple, ingress
interface, shared source MAC, packet path, and (for local process matching) the
socket cookie used to recover the process owner. The separate
`tc_self_sockets` map contains only cookies of sing-box-owned sockets and is
consulted by local egress before any packet interception.
The optional cgroup socket-address tracker records cookie, PID, and UID in a
bounded LRU map. Userspace then reads only `/proc/<pid>/exe` instead of scanning
all process file descriptors. If the tracker cannot be attached, normal route
process search remains the fallback.
Raw-IP shared links mark the source MAC as unavailable rather than publishing a
synthetic address. Source MAC policy therefore requires Ethernet framing.

UDP replies use transparent sockets bound to the original response source. The
inbound reuses one socket per original response source and closes the pool when
the inbound stops.

## Policy routing

Socket assignment preserves the original destination tuple, so selected packets
must also be routed into the local stack. Shared ingress and delivery ingress set
a dynamically allocated packet-mark bit while preserving all other mark bits. Userspace
installs matching IPv4 and IPv6 rules for a dedicated route table containing
local routes for the two halves of each address family. Two `/1` routes are used
instead of one `/0` route because Android kernels can reject a default route of
type `local`.

Policy-routing setup holds a process-external lock, chooses unused mark/table/
priority identifiers, and rejects unrelated routes or rules that already reference
the selected table. Stale matching state from
an interrupted instance is replaced during startup. Rules and routes are added
before the control map is enabled and removed only after interception is
disabled and interface filters are detached.

## Policy order

The programs first apply path-specific address-family, protocol, fragment,
service-traffic, and safety gates. FakeIP forces interception before other
policy. DNS `off` bypasses and DNS `hijack` intercepts before UID or shared source
policy. DNS `respect_policy` applies UID/source policy first, then intercepts
before host, private-address, and destination-CIDR bypass. Other traffic applies
the same source policy followed by those destination bypasses.

Local egress checks the socket-cookie self-bypass map. Shared source CIDR and
MAC include/exclude policies are evaluated only on the shared path.

## Object layout

| Group | Map types | Purpose |
| --- | --- | --- |
| control | `ARRAY` | Enable state, path flags, listener port, and delivery interface identity. |
| sockets and assignments | `SOCKMAP` (optional), `LRU_HASH` | Preferred TCP listener fallback, original-flow metadata, and local self-bypass cookies. Legacy TCP lookup does not use SOCKMAP. |
| prefix policy | `LPM_TRIE` | UID ranges, source CIDRs, and destination bypass CIDRs. |
| exact policy | `HASH` | Host addresses and shared source MAC policy. |

The object is generated for little-endian and big-endian BPF without BTF or
CO-RE sections. Source and object hashes are recorded in
`internal/bpfgen/manifest.txt`.

## Lifecycle

Box construction does not install a process-wide socket wrapper. Shared-only and
unused builds add no socket hooks.

Startup prepares the local self-bypass cookie map during box construction and
attempts the process cgroup socket hooks during the initialize stage. It then
creates listeners, loads maps and programs, registers TCP listeners,
allocates non-conflicting policy-routing identifiers, creates the delivery link when local
mode is configured, attaches available interfaces, loads host and bypass policy,
and enables the control map last. Local mode may start without a default
interface; its egress attachment is added after a network update.

When local process matching is required, startup also attempts to attach the
cgroup socket-address tracker. This is an optional optimization and is closed
with the inbound; shared-only mode never creates self-bypass or process
tracking state.

Default-interface and raw network-update callbacks feed one bounded event queue.
The worker refreshes the interface inventory, follows the current default
interface for local interception, and compares every attachment by name,
ifindex, framing, role, and installed filter identity. It also validates policy
routing and the delivery link after network changes. Missing rules, routes,
filters, delivery link state, and delivery sysctls are restored without periodic
polling.

Configured shared interfaces that are absent at startup are attached when they
appear; deleted or recreated interfaces are detached or replaced. A configured
shared interface is temporarily excluded while it is the current default
upstream and becomes eligible again when it returns to a downstream role. This
allows one Android interface name to alternate between Wi-Fi uplink and hotspot
operation. Topology reconciliation purges userspace UDP state, disables the
control map, replaces attachments and host policy, and then enables the backend.
A failed update attempts to restore the previous state before re-enabling. When
the default interface disappears, the last local attachment is retained until a
new interface is available.

Shutdown stops network and rule-set callbacks, disables interception, closes
listeners and UDP sessions, detaches filters or BPF links,
removes policy routing, restores delivery sysctls, removes the veth, and closes
programs and maps. Startup failures use the same cleanup path.

## Generation and tests

Generated objects use Android NDK r29 Clang 21:

```bash
make -C common/ebpf generate
make -C common/ebpf check
```

Run correctness and ABI tests with:

```bash
go test -tags with_ebpf ./common/ebpf ./protocol/ebpf
```

Kernel program and attachment tests require Linux root privileges and explicit
opt-in:

```bash
sudo env SING_BOX_EBPF_INTEGRATION=1 \
  go test -tags 'with_ebpf ebpf_integration' ./common/ebpf ./protocol/ebpf
```
