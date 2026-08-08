# eBPF inbound backend

This package implements the native eBPF backend used by the sing-box eBPF
inbound.

## Package layout

The Go implementation is grouped by data path and responsibility:

- `cgroup_abi.go`, `cgroup_policy.go`, and `cgroup_mount.go` contain portable
  ABI, policy compilation, and cgroup discovery logic.
- `cgroup_backend_cgo.go`, `cgroup_socket_cgo.go`, and
  `cgroup_policy_cgo.go` manage the native cgroup runtime, socket redirect
  maps, and live policy maps.
- `shared_network_abi.go` and `shared_network_policy.go` contain the portable
  TC map ABI and host-address policy compilation.
- `shared_network_cgo.go`, `shared_network_flow_cgo.go`, and
  `shared_network_policy_cgo.go` manage the native TC runtime, flow maps, and
  live host-address maps.
- `backend_cgo.go` contains memlock, capability-probe, and load-error helpers
  shared by the cgroup and TC backends.
- `map.go` contains the small BPF map syscall boundary shared by both data
  paths. Files ending in `_stub.go` preserve the same API when cgo is disabled.

## Native layout

The Go and `cgo_*.c` files in this directory form the cgo boundary. cgo only
compiles C files located directly in the package directory, so the wrappers
include implementation files from `native/`:

- `native/cgroup.c` contains the shared cgroup definitions and includes the
  program and runtime implementation in one cgo translation unit.
- `native/cgroup.bpf.c` and `native/shared_network.bpf.c` are compiled to the
  embedded cgroup and TC ingress/egress objects.
- `native/cgroup_loader.c` selects cgroup object sections, loads them, and
  retains the TGID to socket-cookie compatibility fallback.
- `native/cgroup_runtime.c` creates the cgroup maps and manages prepare,
  attach, and close operations.
- `native/object_loader.c` validates, relocates, and loads both objects without
  libbpf. Backend-specific map and program tables live in
  `native/cgroup_loader.c` and `native/shared_network_loader.c`.
- `native/shared_network_runtime.c` creates and manages the shared-network
  maps and programs.
- `native/bpf.c` contains the BPF syscall, loader, attach, and cleanup
  helpers.
- `native/abi.h` contains only the cgroup map ABI shared by userspace and BPF
  C. `native/runtime.h` is the private userspace runtime API shared with Go.

Helpers used only by one native component remain static in that component
instead of being exposed through `native/runtime.h`.

## Embedded eBPF objects

`native/cgroup.bpf.o` and `native/shared_network.bpf.o` are generated and
intentionally not tracked. They are architecture-neutral `bpfel` bytecode
consumed by `go:embed`, rather than Android or Linux native objects. Their GPL
sources are `native/cgroup.bpf.c` and `native/shared_network.bpf.c`.

The regular cgo compiler cannot create these objects as part of its Android or
Linux C compilation: cgo produces native machine code, while the cgroup and TC
programs must be compiled separately with `-target bpfel`. When `TAGS` contains
`with_ebpf`, the root `make build` target performs that generation automatically.
Generate them explicitly before direct `go build` or `go test` commands:

```sh
ANDROID_NDK_HOME=/usr/share/android-ndk-r29 make ebpf_generate
```

The generated objects remain ignored by Git. `make ebpf_check` is available
for local reproducibility checks after generation. Both use the baseline BPF
v1 instruction set so changing the host or NDK Clang does not silently raise
the kernel instruction-set requirement.

When native IPv6 interception is disabled, the cgroup loader selects smaller
IPv4-mapped `connect6`, `sendmsg6`, and `recvmsg6` sections. These preserve
IPv4 traffic from dual-stack applications without loading the unused native
IPv6 policy and redirect path. Dual-stack configurations continue to select
the complete IPv6 sections.

## Testing

Run the focused Linux tests with cgo, without cgo, and under the race detector:

```sh
CGO_ENABLED=1 go test -tags with_ebpf ./common/ebpf ./protocol/ebpf ./include
CGO_ENABLED=0 go test -tags with_ebpf ./common/ebpf ./protocol/ebpf ./include
CGO_ENABLED=1 go test -race -tags with_ebpf ./common/ebpf ./protocol/ebpf ./include
```

An Android cross-build validates the NDK headers, native ABI, and cgo boundary:

```sh
GOOS=android GOARCH=arm64 CGO_ENABLED=1 \
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang" \
go test -c -tags with_ebpf -o /tmp/sing-box-ebpf-android.test ./protocol/ebpf
```

The root integration tests are excluded from normal test builds and require
the `ebpf_integration` build tag. The program-load test creates the maps and
asks the kernel verifier to load the IPv4 and dual-stack program matrix with
TCP, UDP, or both protocols, DNS hijack enabled or disabled, automatic IPv6
availability enabled or disabled, and TGID or socket-cookie self bypass. It
also covers the socket-release program when the kernel supports it and the UDP
LRU fallback otherwise, then closes everything without attaching. The traffic
test creates a temporary child cgroup and verifies IPv4
TCP redirection, original destination and UID recovery, and DNS-priority UDP
redirection through a configured private CIDR bypass. It also passes protected
TCP and UDP sockets into the child cgroup and verifies that socket-cookie self
bypass prevents them from returning to the redirect listeners. The program-load
target cgroup is auto-detected unless `SING_BOX_EBPF_INTEGRATION_CGROUP` is set.
The standalone shared-network load test verifies that the TC backend can create
and populate its own bypass maps without a cgroup backend:

```sh
sudo -E SING_BOX_EBPF_INTEGRATION=1 \
go test -count=1 \
  -run 'Test(CgroupBackend(ProgramLoad|Traffic)|SharedNetwork(SharedMap|Standalone)ProgramLoad)Integration' \
  -tags with_ebpf,ebpf_integration ./common/ebpf
```

The shared-network integration test additionally creates a temporary network
namespace and veth pair. It verifies IPv4 and IPv6 public TCP interception,
a large TCP payload through the TC/GSO path, dual-stack fragmented UDP round
trips, dual-stack DNS capture to the gateway in the default hijack mode, DHCP
bypass, fail-closed behavior at map capacity, reply source restoration, TC
cleanup, local redirect routes, and
`route_localnet` restoration. It requires `ip` and `nc`:

```sh
sudo -E SING_BOX_EBPF_SHARED_INTEGRATION=1 \
go test -count=1 -run TestSharedNetworkDataPathIntegration \
  -tags with_ebpf,ebpf_integration ./protocol/ebpf
```

Setting `SING_BOX_EBPF_INTEGRATION_ATTACH=1` also attaches each program before
cleanup. Use that mode only with an empty, dedicated cgroup passed through
`SING_BOX_EBPF_INTEGRATION_CGROUP`; attaching to a populated root cgroup can
briefly affect unrelated traffic. Preparing the target also removes stale
programs whose names start with `sb_ebpf_`.

For Android soak tests, record the startup program list and monitor the Clash
API connection view while exercising repeated short TCP connections, UDP
session expiry, and connected UDP socket churn. Traffic should continue to use
the correct original destination without persistent lookup or map operation
errors in the log.

## Credits

The native interception implementation is based on
[Asterisk4Magisk/bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks) and
has been adapted for direct integration as a sing-box inbound, without a SOCKS
bridge.

The derived native source remains available under GPL-3.0. See
[`native/LICENSE`](native/LICENSE).
