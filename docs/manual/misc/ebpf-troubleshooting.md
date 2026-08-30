# eBPF inbound troubleshooting

Provide a complete report from startup through one reproduction and shutdown.
Startup-only logs rarely explain intermittent packet loss, attachment changes,
or resource growth.

## Minimum report

Include:

1. The exact sing-box commit or full `sing-box version` output and build tags.
2. The eBPF inbound configuration and relevant route rules. Remove credentials,
   but retain enabled/data-plane settings, interfaces, UID or source policy, DNS and IPv6 settings, TC
   priority, and bypass policy.
3. Device model, operating-system release, complete kernel release, and, on
   Android, the build fingerprint.
4. Debug-level logs from startup through reproduction and graceful shutdown.
5. Reproduction steps, expected and actual behavior, affected protocol, local
   or downstream scope, and whether restarting sing-box changes the result.
6. A capability report matching the intended path:

```sh
sing-box tools ebpf status --local-data-plane cgroup --network tcp,udp --json
sing-box tools ebpf status --shared-data-plane packet_rewrite --interface br-lan --json
```

Add `--ipv6=false` when the inbound configuration disables IPv6. The command
exits non-zero when a required capability is missing or cannot be verified.

For a configuration that enables both paths, pass both data-plane flags in one
command. Run probes with the same privileges as the service.

Useful platform information:

```sh
uname -a
cat /proc/version
cat /proc/meminfo
ip -details link show
tc -details qdisc show
tc -statistics -details filter show
```

Android reports should also include `getprop ro.build.fingerprint` and a full
`logcat -b all -d`. OpenWrt reports should include `/etc/openwrt_release` and
`ubus call system board`.

## Kernel panic or device restart

After restart, copy `/sys/fs/pstore` before another crash overwrites it:

```sh
ls -la /sys/fs/pstore
cp -a /sys/fs/pstore ./pstore-copy
dmesg -T > dmesg-after-reboot.txt
```

Include `console-ramoops-*`, `dmesg-ramoops-*`, and `pmsg-ramoops-*` files when
present. State whether local mode, shared mode, or only a network-interface
change triggers the restart. The kernel record is more useful than a userspace
log that stops before the fault.

## Logs and runtime state

At Debug log level, a successful startup emits an `eBPF cgroup active` or
`eBPF TC active` summary containing the selected data planes and their effective
runtime paths. TC summaries also include the default interface, attachments,
internal listeners, routing state, and delivery interface when applicable. Each
attachment includes its local/shared role and framing. A network event emits a
Debug entry only when attachments or managed network state are changed; repair
failures produce rate-limited warnings. Userspace handoff failures produce
rate-limited Warn or Error entries. BPF packet return paths do not emit
per-packet logs, and interface lifecycle handling does not use periodic polling.
Shared `packet_rewrite` runs a bounded adaptive sweep to reclaim orphaned flow
state. Normal pressure scans are requested by flow-state events; a low-frequency
watchdog also checks for kernel-only orphans that userspace cannot observe. This
maintenance does not emit periodic status records.

If the log reports an assignment or UDP original-destination failure, retain
the complete log around the first error and collect the TC attachment state
described below.

## CPU and memory profiles

Enable the standard debug endpoint on loopback to use Go pprof:

```json
{
  "experimental": {
    "debug": {
      "listen": "127.0.0.1:6060"
    }
  }
}
```

Then collect CPU, heap, and goroutine profiles around the reproduction:

```sh
curl -o cpu.pprof 'http://127.0.0.1:6060/debug/pprof/profile?seconds=30'
curl -o heap.pprof 'http://127.0.0.1:6060/debug/pprof/heap?gc=1'
curl -o goroutine.txt 'http://127.0.0.1:6060/debug/pprof/goroutine?debug=2'
go tool pprof -top cpu.pprof
go tool pprof -top heap.pprof
```

pprof measures Go userspace CPU and memory, not BPF execution or kernel map
memory. Use TC state, `dmesg`, and BPF inspection tools available on the target
system for the kernel side.

## Attachment and interface checks

Local `cgroup` mode follows the selected cgroup v2 hierarchy and has no network
interface attachment. Local `tc` follows the current default interface. Shared
mode follows the configured downstream interfaces and retries interfaces that
were absent at startup. A configured shared interface is detached while it is
the current default upstream and restored when it becomes downstream again. Network events also
validate the managed TC filters, policy routing, and delivery link. When
interception changes after an interface event, capture before and after output
from:

```sh
ip -details link show
ip route show table all
ip -6 route show table all
tc -details qdisc show
tc -statistics -details filter show
```

Also retain the startup `eBPF TC active` summary. Do not manually remove the
internal veth or managed TC filters while sing-box is running.

For local `tc` interception, compare the packet counts on the default-interface
egress filter and the logged delivery-interface ingress filter:

```sh
tc -statistics filter show dev wlan0 egress
tc -statistics filter show dev sbdXXXXXXXX ingress
```

Replace both interface names with those from the startup log. If the local
filter count increases while the delivery filter does not, retain both filter
outputs and the corresponding `ip -details link show` output.

## Privacy

Logs and profiles can contain destination addresses, domains, interface and
package names, file paths, and configuration fragments. Remove credentials and
unrelated personal data, while preserving timestamps, error numbers, program
and map IDs, UID ranges, kernel stack traces, and event order.
