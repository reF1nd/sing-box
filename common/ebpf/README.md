# sing-box eBPF inbound backend

This directory contains the native eBPF backend used by the sing-box eBPF
inbound. It is a maintainer document; user-facing configuration and platform
requirements live in [`docs/configuration/inbound/ebpf.md`](../../docs/configuration/inbound/ebpf.md).

## Responsibilities

The Go side owns object loading, map lifetime, cgroup and TC attachments, policy
compilation, and listener integration. The native C side is the packet and
socket data path. The runtime uses `github.com/cilium/ebpf` and has no cgo
boundary or process-global probe.

| Area | Files | Responsibility |
|------|-------|----------------|
| cgroup path | `cgroup_*.go`, `redirect_address*.go` | Local socket hooks, redirect maps, UID policy, cgroup discovery, and original-destination state |
| shared path | `shared_network_*.go` | TC links, interface lifecycle, source/MAC policy, flow state, and host-address bypass maps |
| common runtime | `loader.go`, `backend_runtime.go`, `map.go`, `kernel_*.go` | cilium object loading, direct map syscalls, feature probes, memlock, and `tools ebpf status` |
| native data path | `native/cgroup.bpf.c`, `native/shared_network.bpf.c`, `native/*.h` | Verifier-friendly socket and packet programs plus explicit map ABI |
| generated objects | `internal/bpfgen/` | `bpf2go` bindings, endian-specific BPF objects, and the generation manifest |

The native sources are intentionally split into policy, packet parsing, flow,
and checksum helpers, but are compiled as one verifier-visible translation unit
per entry point. Shared ingress and egress have separate entry points so each
loaded program remains below the Linux 4.19 4096-instruction limit.

## Generated objects

`internal/bpfgen/*_bpf{el,eb}.o` and their Go bindings are checked in. They are
architecture-neutral BPF bytecode, not Android or host-native objects. Both byte
orders are shipped so a big-endian OpenWrt target does not silently load a
little-endian object. Normal builds consume these files and do not invoke a C
compiler:

```sh
CGO_ENABLED=0 TAGS=with_ebpf make build
```

Regeneration is a maintainer operation. It uses Android NDK r29 Clang 21 and
the NDK Linux UAPI sysroot, even when the final binary targets Linux:

```sh
ANDROID_NDK_HOME=/usr/share/android-ndk-r29 make ebpf_generate
make ebpf_check
```

The Makefile clears ambient include-path variables, passes `-nostdinc`, and
allows only Clang resource headers, `native`, and the pinned NDK sysroot. The
`bpf2go` Go generator always runs as the build-host platform; `BPF_CLANG` still
controls the compiler used for the BPF C sources. `manifest.txt` records the
normalized flags, tool versions, source hashes, and object hashes.

## Compatibility invariants

- Shared mode and TCP-only local mode target Linux 4.19. Local UDP needs the
  upstream 5.2 cgroup UDP recvmsg attach types or a vendor backport.
- Android GKI 5.10+ and standard Linux/OpenWrt are the primary validation
  targets. Capability probes are authoritative because vendor kernels backport
  features independently.
- Programs use the BPF v1 instruction set and do not require BTF, CO-RE,
  bounded-loop verification, BPF timers, dynptrs, kfuncs, or pinned bpffs state.
  Default-priority shared-network attachment uses TCX when available and
  otherwise falls back to clsact.
- Shared host addresses use exact-match hash maps. They are not prefixes, and
  this avoids the Linux 6.6.0 through 6.6.46 LPM-trie UBSAN issue. UID/package
  filters and prefix-based CIDR policies still use LPM tries and are rejected
  on a known-unfixed kernel.
- IPv4 and native IPv6 sections are selected independently. When native IPv6 is
  disabled, smaller IPv4-mapped cgroup sections are loaded.

## Tests and diagnostics

Run the focused tests without cgo:

```sh
CGO_ENABLED=0 go test -tags with_ebpf \
  ./common/ebpf ./protocol/ebpf ./include ./option
```

An Android cross-test checks build tags and generated ABI without running the
test binary on Android:

```sh
GOOS=android GOARCH=arm64 CGO_ENABLED=0 \
  go test -c -tags with_ebpf -o /tmp/sing-box-ebpf-android.test ./protocol/ebpf
```

Privileged integration tests are opt-in. The load test exercises the cgroup and
standalone shared program matrix; the datapath test creates a temporary network
namespace and veth pair:

```sh
sudo -E SING_BOX_EBPF_INTEGRATION=1 \
  go test -count=1 -tags with_ebpf,ebpf_integration \
  -run 'Test(CgroupBackend|SharedNetwork).*Integration' ./common/ebpf

sudo -E SING_BOX_EBPF_SHARED_INTEGRATION=1 \
  go test -count=1 -tags with_ebpf,ebpf_integration \
  -run TestSharedNetworkDataPathIntegration ./protocol/ebpf
```

The maintenance benchmark compares a full batch scan with one bounded legacy
fallback janitor tick over a populated 65536-entry hash map:

```sh
sudo -E SING_BOX_EBPF_INTEGRATION=1 \
  go test -run '^$' -bench BenchmarkMapScanMaintenance -benchmem \
  -tags with_ebpf,ebpf_integration ./common/ebpf
```

Use an empty, dedicated cgroup when testing attachment. On a target device,
capture the non-disruptive capability report before debugging traffic:

```sh
sing-box tools ebpf status --mode local --network tcp,udp
sing-box tools ebpf status --mode shared-network --interface br-lan
```

The status command creates transient probe objects and closes them immediately;
it does not attach programs or change routes, qdiscs, sysctls, cgroups, or
traffic.

For a temporary diagnostic build, add the `ebpf_debug` tag together with
`with_ebpf`. It adds one-minute runtime snapshots with Go heap, RSS, GC,
goroutine, and maintenance-task timing counters. It does not add probes to the
packet hot path. Set `SING_BOX_EBPF_PPROF_PORT` to a TCP port to expose Go
pprof on `127.0.0.1` only; the endpoint is disabled when the variable is
unset. See the [troubleshooting guide](../../docs/manual/misc/ebpf-troubleshooting.md)
for collection commands and scope limitations.

## Credits

The native interception implementation is based on
[Asterisk4Magisk/bpf2socks](https://github.com/Asterisk4Magisk/bpf2socks) and is
adapted for direct integration as a sing-box inbound without a SOCKS bridge.
The derived native source remains available under GPL-3.0; see
[`native/LICENSE`](native/LICENSE).
