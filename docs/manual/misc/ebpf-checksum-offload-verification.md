# eBPF checksum/offload verification

This procedure verifies that packets rewritten by the eBPF TC data planes
remain wire-correct with checksum and segmentation offload enabled. It covers
`shared.data_plane: packet_rewrite`, FakeIP ICMP replies, and an untouched
bypass control flow.

The procedure requires real hardware. Veth, loopback, and virtio paths finish
offload in software and cannot expose NIC firmware or driver defects. Use a
physical NIC or an SR-IOV/passthrough virtual function, and record its model,
driver, firmware, and kernel with the report.

## Hosts

- **DUT** runs sing-box and this tool. `LOCAL_IFACE` names the physical
  interface carrying the eBPF attachment.
- **REMOTE_HOST** is a real destination reachable from the DUT and over
  non-interactive SSH. It receives control, TCP, and UDP traffic and captures
  the remote side of each run.
- **DOWNSTREAM_HOST** is required for shared testing. It originates traffic
  through the DUT's shared-facing interface, because DUT-originated traffic
  cannot exercise shared ingress.

For unambiguous attribution, enable only the role under test. If both roles
are active, `/ebpf` counters are aggregated across their backends.

## Prerequisites

- Root on all involved hosts and key-based SSH from the DUT.
- Go, `ethtool`, `tcpdump`, and `nc` on the DUT.
- `tcpdump` and `nc` on `REMOTE_HOST`; `nc` on `DOWNSTREAM_HOST`.
- A running sing-box eBPF inbound attached to `LOCAL_IFACE`.
- `fakeip_icmp: reply` for ICMP checks.
- `shared.data_plane: packet_rewrite` for shared TCP/UDP checks.
- Optionally, the Clash API `/ebpf` endpoint for counter-based attribution.

Confirm that the interface uses a hardware driver:

```sh
ethtool -i eth0
```

Drivers such as `ixgbe`, `i40e`, `mlx5_core`, `r8169`, and `igc` are suitable.
`veth`, `virtio_net`, and `vmxnet3` are not suitable for this test.

## Configuration

Required environment variables:

| Variable | Meaning |
|---|---|
| `LOCAL_IFACE` | DUT interface carrying the eBPF attachment |
| `REMOTE_HOST` | SSH-reachable receiving host |
| `FAKEIP_PREFIX` | Configured FakeIP CIDR |
| `REMOTE_FAKEIP_TARGET` | Address inside `FAKEIP_PREFIX` |

Optional variables:

| Variable | Default | Meaning |
|---|---:|---|
| `TEST_ROLE` | `both` | `local`, `shared`, or `both` |
| `DOWNSTREAM_HOST` | — | Required for `shared` and `both` |
| `REMOTE_SSH_USER` | `root` | Remote SSH user |
| `DOWNSTREAM_SSH_USER` | remote user | Downstream SSH user |
| `SSH` | `ssh -o BatchMode=yes -o ConnectTimeout=5` | Remote SSH command |
| `DOWNSTREAM_SSH` | same default | Downstream SSH command |
| `REMOTE_IPV6` | — | FakeIP IPv6 target; enables IPv6 ping checks |
| `REMOTE_PORT_TCP` | — | Enables TCP content verification |
| `REMOTE_PORT_UDP` | — | Enables UDP content verification |
| `DUT_DIAGNOSTICS_URL` | — | Clash API `/ebpf` URL |
| `DUT_DIAGNOSTICS_TOKEN` | — | Optional bearer token |
| `PING_COUNT` | `20` | Pings per ICMP check |
| `TRANSFER_BYTES` | `8388608` | TCP payload size |
| `OUT_DIR` | `./checksum-offload-report` | Report and capture directory |

`TEST_ROLE=shared` and `TEST_ROLE=both` require `DOWNSTREAM_HOST`. Excluded
roles are recorded as `NOT_TESTED` rather than silently omitted.

## Run

Build as an ordinary user, then run the resulting tool as root:

```sh
go build -o /tmp/sing-box-checksumoffload github.com/CHIZI-0618/sing-ebpf/testing/checksumoffload

sudo LOCAL_IFACE=eth0 \
    REMOTE_HOST=192.0.2.10 \
    REMOTE_SSH_USER=root \
    DOWNSTREAM_HOST=192.0.2.20 \
    DOWNSTREAM_SSH_USER=root \
    DUT_DIAGNOSTICS_URL=http://127.0.0.1:9090/ebpf \
    FAKEIP_PREFIX=198.18.0.0/15 \
    REMOTE_FAKEIP_TARGET=198.18.0.1 \
    REMOTE_IPV6=fdfe:dcba:9876::1 \
    REMOTE_PORT_TCP=15000 \
    REMOTE_PORT_UDP=15001 \
    TEST_ROLE=both \
    /tmp/sing-box-checksumoffload
```

The tool saves the original offload state and restores it on normal exit,
failure, SIGINT, or SIGTERM. It tests four complete feature combinations:

- all relevant features enabled;
- all disabled;
- TX checksum offload disabled;
- TSO, GSO, and UDP segmentation disabled.

Every requested state is read back. A driver refusal or unsupported feature
marks the combination `UNSUPPORTED`, and traffic checks do not run under a
misleading label.

For each applied combination the tool:

1. Starts DUT and remote packet captures.
2. Verifies an untouched SSH control flow.
3. Runs local and/or downstream-originated FakeIP ICMP checks.
4. Runs optional TCP and UDP transfers and compares full SHA-256 payloads.
5. Checks shared FakeIP and rewrite counters when diagnostics are configured.
6. Writes `report.tsv` and local/remote PCAP files under `OUT_DIR`.

The receiving payload is authoritative. A sending-side capture can report an
incorrect checksum before the NIC has completed TX offload.

## Exit status

- `0`: at least one check passed; no failures or unsupported combinations.
- `1`: at least one check failed.
- `2`: inconclusive; no check passed.
- `3`: partial; checks passed but at least one combination was unsupported.
- `4`: report creation or writing failed.

An `UNSUPPORTED` result describes the NIC/driver state, not eBPF behavior. If
the bypass control fails, fix the hardware/offload setup before interpreting
rewrite failures. When the control passes but a rewritten flow fails, inspect
the remote capture first and attach both PCAP files to the report.

## Limits

- Android hardware and tooling require a separate device procedure.
- The tool does not select TCX versus `clsact`; test each sing-box attachment
  configuration separately.
- Extend `offloadFeatures` and `offloadMatrix` in the Go source for additional
  vendor features, assigning every feature in every combination.
- Aggregated diagnostics cannot fully attribute traffic while both local and
  shared backends host the FakeIP responder.
