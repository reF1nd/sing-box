# eBPF inbound backend

This package implements the native eBPF backend used by the sing-box eBPF
inbound.

The Go and `cgo_*.c` files in this directory form the cgo boundary. cgo only
compiles C files located directly in the package directory, so the wrappers
include implementation files from `native/`:

- `native/connect_prog.c` builds and manages the inbound maps and programs.
- `native/shared_network.bpf.c` is compiled to the embedded
  `native/shared_network.bpf.o` TC ingress/egress object.
- `native/shared_network_loader.c` relocates and loads that object without
  libbpf.
- `native/shared_network_runtime.c` creates and manages the shared-network
  maps and programs.
- `native/bpf_util.c` contains the BPF syscall, loader, attach, and cleanup
  helpers.
- `native/singbox_ebpf.h` is the private ABI shared with the Go backend.

Small helpers used only by the program builder are kept static in
`connect_prog.c` instead of being exposed as separate translation units.

## Embedded TC object

`native/shared_network.bpf.o` is generated and intentionally not tracked. It
is architecture-neutral `bpfel` bytecode consumed by `go:embed`, rather than
an Android or Linux native object. The corresponding GPL source is
`native/shared_network.bpf.c`.

The regular cgo compiler cannot create this object as part of its Android or
Linux C compilation: cgo produces native machine code, while a TC program must
be compiled separately with `-target bpfel`. When `TAGS` contains `with_ebpf`,
the root `make build` target performs that generation automatically. Generate
it explicitly before direct `go build` or `go test` commands:

```sh
ANDROID_NDK_HOME=/usr/share/android-ndk-r25c make ebpf_generate
```

The generated object remains ignored by Git. `make ebpf_check` is available
for local reproducibility checks after generation.

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
CC="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android33-clang" \
go test -c -tags with_ebpf -o /tmp/sing-box-ebpf-android.test ./protocol/ebpf
```

The root integration test is skipped by default. With
`SING_BOX_EBPF_INTEGRATION=1`, it creates the maps and asks the kernel verifier
to load every dual-stack TCP/UDP program, including the socket-release program,
then closes everything without attaching. The target cgroup is auto-detected
unless `SING_BOX_EBPF_INTEGRATION_CGROUP` is set:

```sh
sudo -E SING_BOX_EBPF_INTEGRATION=1 \
go test -count=1 -run TestBackendProgramLoadIntegration -tags with_ebpf ./common/ebpf
```

The shared-network integration test additionally creates a temporary network
namespace and veth pair. It verifies IPv4 and IPv6 public TCP interception,
dual-stack DNS capture to the gateway in the default hijack mode, DHCP bypass,
reply source restoration, TC cleanup, local redirect routes, and
`route_localnet` restoration. It requires `ip` and `nc`:

```sh
sudo -E SING_BOX_EBPF_SHARED_INTEGRATION=1 \
go test -count=1 -run TestSharedNetworkDataPathIntegration -tags with_ebpf ./protocol/ebpf
```

Setting `SING_BOX_EBPF_INTEGRATION_ATTACH=1` also attaches each program before
cleanup. Use that mode only with an empty, dedicated cgroup passed through
`SING_BOX_EBPF_INTEGRATION_CGROUP`; attaching to a populated root cgroup can
briefly affect unrelated traffic. Preparing the target also removes stale
programs whose names start with `sb_ebpf_`.

For Android soak tests, record the startup program list and the periodic/final
`eBPF runtime metrics` lines. After repeated short TCP connections, UDP session
expiry, and connected UDP socket churn, TCP occupancy should return promptly,
UDP occupancy should plateau instead of growing with cumulative traffic, and
redirect drops, update failures, and lookup misses should remain zero.

## Credits

The native interception implementation is based on
[Asterisk4Magisk/bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks) and
has been adapted for direct integration as a sing-box inbound, without a SOCKS
bridge.

The derived native source remains available under GPL-3.0. See
[`native/LICENSE`](native/LICENSE).
