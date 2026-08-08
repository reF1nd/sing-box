#!/bin/sh

# Non-disruptive capability probe for the sing-box eBPF inbound.
# Compatible with Android Toybox, OpenWrt BusyBox, and regular Linux userlands.

set -u

mode=all
cgroup_path=
interface_name=
pass_count=0
warn_count=0
fail_count=0
unknown_count=0
required_fail_count=0
temporary_directory=

usage() {
	cat <<'EOF'
Usage: check-kernel.sh [options]

Options:
  --mode all|local|shared-network
                              Select the data path to check (default: all).
  --cgroup PATH               Check this cgroup v2 path instead of auto-detecting it.
  --interface INTERFACE       Also check a shared-network downstream interface.
  -h, --help                  Show this help.

The probe does not attach programs, change routes, sysctls, qdiscs, or traffic.
When bpftool is available it performs transient kernel feature probes.  Without
bpftool, it falls back to the running kernel configuration and filesystem state;
features that cannot be proven safely are reported as UNKNOWN.
EOF
}

while [ "$#" -gt 0 ]; do
	case "$1" in
		--mode)
			[ "$#" -ge 2 ] || { echo "missing value for --mode" >&2; exit 2; }
			mode=$2
			shift 2
			;;
		--cgroup)
			[ "$#" -ge 2 ] || { echo "missing value for --cgroup" >&2; exit 2; }
			cgroup_path=$2
			shift 2
			;;
		--interface)
			[ "$#" -ge 2 ] || { echo "missing value for --interface" >&2; exit 2; }
			interface_name=$2
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			echo "unknown option: $1" >&2
			usage >&2
			exit 2
			;;
	esac
done

case "$mode" in
	all|local|shared-network) ;;
	*)
		echo "invalid mode: $mode" >&2
		exit 2
		;;
esac

cleanup() {
	if [ -n "$temporary_directory" ]; then
		rm -rf "$temporary_directory" 2>/dev/null || true
	fi
}
trap cleanup 0 1 2 3 15

make_temporary_directory() {
	for base in "${TMPDIR:-}" /data/local/tmp /tmp; do
		[ -n "$base" ] || continue
		[ -d "$base" ] && [ -w "$base" ] || continue
		temporary_directory=$(mktemp -d "$base/sing-box-ebpf-probe.XXXXXX" 2>/dev/null) || temporary_directory=
		[ -n "$temporary_directory" ] && return 0
	done
	echo "cannot create a temporary directory" >&2
	exit 2
}
make_temporary_directory

report() {
	status=$1
	scope=$2
	importance=$3
	feature=$4
	description=$5
	case "$status" in
		PASS) pass_count=$((pass_count + 1)) ;;
		WARN) warn_count=$((warn_count + 1)) ;;
		FAIL)
			fail_count=$((fail_count + 1))
			[ "$importance" = required ] && required_fail_count=$((required_fail_count + 1))
			;;
		UNKNOWN) unknown_count=$((unknown_count + 1)) ;;
	esac
	printf '%-7s [%-14s] [%-11s] %s\n' "$status" "$scope" "$importance" "$feature"
	printf '        %s\n' "$description"
}

has_command() {
	command -v "$1" >/dev/null 2>&1
}

kernel_release=$(uname -r 2>/dev/null || echo unknown)
machine=$(uname -m 2>/dev/null || echo unknown)
platform=Linux
if has_command getprop && [ -n "$(getprop ro.build.version.sdk 2>/dev/null || true)" ]; then
	platform=Android
elif [ -r /etc/openwrt_release ]; then
	platform=OpenWrt
fi

kernel_config="$temporary_directory/kernel.config"
kernel_config_source=
load_kernel_config() {
	if [ -r /proc/config.gz ]; then
		if has_command gzip && gzip -dc /proc/config.gz >"$kernel_config" 2>/dev/null; then
			kernel_config_source=/proc/config.gz
			return 0
		fi
		if has_command zcat && zcat /proc/config.gz >"$kernel_config" 2>/dev/null; then
			kernel_config_source=/proc/config.gz
			return 0
		fi
	fi
	for candidate in "/boot/config-$kernel_release" "/lib/modules/$kernel_release/build/.config"; do
		if [ -r "$candidate" ]; then
			cp "$candidate" "$kernel_config" 2>/dev/null || continue
			kernel_config_source=$candidate
			return 0
		fi
	done
	: >"$kernel_config"
	return 1
}
load_kernel_config || true

config_value() {
	option=$1
	[ -n "$kernel_config_source" ] || return 1
	value=$(grep "^CONFIG_${option}=" "$kernel_config" 2>/dev/null | sed -n '1s/^[^=]*=//p')
	if [ -n "$value" ]; then
		printf '%s\n' "$value"
		return 0
	fi
	if grep "^# CONFIG_${option} is not set$" "$kernel_config" >/dev/null 2>&1; then
		printf '%s\n' n
		return 0
	fi
	return 1
}

check_config() {
	scope=$1
	importance=$2
	option=$3
	description=$4
	value=$(config_value "$option" 2>/dev/null || true)
	case "$value" in
		y)
			report PASS "$scope" "$importance" "CONFIG_$option=y" "$description"
			;;
		m)
			report WARN "$scope" "$importance" "CONFIG_$option=m" "$description The matching kernel module must be loaded before sing-box starts."
			;;
		n)
			report FAIL "$scope" "$importance" "CONFIG_$option is disabled" "$description"
			;;
		*)
			report UNKNOWN "$scope" "$importance" "CONFIG_$option" "$description The running kernel configuration is not readable."
			;;
	esac
}

bpftool_output="$temporary_directory/bpftool-feature.txt"
bpftool_error="$temporary_directory/bpftool-feature.err"
bpftool_probed=0
if has_command bpftool; then
	if bpftool feature probe kernel full >"$bpftool_output" 2>"$bpftool_error" ||
		bpftool feature probe kernel >"$bpftool_output" 2>"$bpftool_error"; then
		bpftool_probed=1
	fi
fi

bpftool_has() {
	grep "$1" "$bpftool_output" >/dev/null 2>&1
}

check_program_type() {
	scope=$1
	importance=$2
	type=$3
	description=$4
	if [ "$bpftool_probed" -eq 1 ]; then
		if bpftool_has "program_type $type is available"; then
			report PASS "$scope" "$importance" "BPF program type $type" "$description"
		else
			report FAIL "$scope" "$importance" "BPF program type $type" "$description bpftool could not load this program type."
		fi
	else
		report UNKNOWN "$scope" "$importance" "BPF program type $type" "$description Install bpftool for a real load probe; kernel configuration alone cannot prove a program type."
	fi
}

check_map_type() {
	scope=$1
	importance=$2
	type=$3
	description=$4
	if [ "$bpftool_probed" -eq 1 ]; then
		if bpftool_has "map_type $type is available"; then
			report PASS "$scope" "$importance" "BPF map type $type" "$description"
		else
			report FAIL "$scope" "$importance" "BPF map type $type" "$description bpftool could not create this map type."
		fi
	else
		report UNKNOWN "$scope" "$importance" "BPF map type $type" "$description Install bpftool to test map creation directly."
	fi
}

bpftool_has_helper_section() {
	grep "helpers supported for program type $1:" "$bpftool_output" >/dev/null 2>&1
}

bpftool_has_helper() {
	program=$1
	helper=$2
	awk -v program="$program" -v helper="$helper" '
		/helpers supported for program type / {
			active = index($0, "program type " program ":") != 0
		}
		active && index($0, helper) != 0 { found = 1 }
		END { exit found ? 0 : 1 }
	' "$bpftool_output"
}

check_helper() {
	scope=$1
	importance=$2
	program=$3
	helper=$4
	description=$5
	if [ "$bpftool_probed" -eq 1 ] && bpftool_has_helper_section "$program"; then
		if bpftool_has_helper "$program" "bpf_$helper"; then
			report PASS "$scope" "$importance" "bpf_$helper for $program" "$description"
		elif [ "$importance" = required ]; then
			report FAIL "$scope" "$importance" "bpf_$helper for $program" "$description"
		else
			report WARN "$scope" "$importance" "bpf_$helper for $program" "$description The optimized path is unavailable."
		fi
	else
		report UNKNOWN "$scope" "$importance" "bpf_$helper for $program" "$description bpftool helper probing is unavailable."
	fi
}

show_active_state() {
	echo
	echo "Active sing-box eBPF state"
	if [ "$bpftool_probed" -eq 1 ]; then
		program_output="$temporary_directory/bpftool-programs.txt"
		if bpftool prog show >"$program_output" 2>/dev/null; then
			active_output="$temporary_directory/bpftool-active-programs.txt"
			awk '
				/^[0-9]+:/ { active = index($0, " name sb_ebpf_") != 0 || index($0, " name sb_share_") != 0 }
				active { print }
			' "$program_output" >"$active_output"
			if [ -s "$active_output" ]; then
				echo "Programs:"
				sed 's/^/  /' "$active_output"
				map_ids=$(awk '
					/^[0-9]+:/ { active = index($0, " name sb_ebpf_") != 0 || index($0, " name sb_share_") != 0 }
					active && /map_ids / {
						sub(/^.*map_ids /, "")
						gsub(/,/, " ")
						print
					}
				' "$program_output" | tr ' ' '\n' | sed '/^$/d' | sort -u)
				if [ -n "$map_ids" ]; then
					echo "Referenced maps:"
					for map_id in $map_ids; do
						bpftool map show id "$map_id" 2>/dev/null | sed 's/^/  /' || true
					done
					echo "  Occupancy is not dumped because walking large flow maps can disturb a live data path."
				fi
			else
				echo "Programs: none with a sing-box eBPF name are currently visible."
			fi
		else
			echo "Programs: bpftool could not enumerate programs."
		fi
		cgroup_output=$(bpftool cgroup tree 2>/dev/null | awk 'index($0, "sb_ebpf_") != 0 { print }')
		if [ -n "$cgroup_output" ]; then
			echo "Cgroup attachments:"
			printf '%s\n' "$cgroup_output" | sed 's/^/  /'
		else
			echo "Cgroup attachments: none visible, or cgroup tree enumeration is unavailable."
		fi
	else
		echo "Programs/maps/cgroup attachments: install bpftool and run with sufficient privileges."
	fi

	if [ -n "$interface_name" ]; then
		if has_command tc && [ -d "/sys/class/net/$interface_name" ]; then
			echo "TC filters on $interface_name:"
			for direction in ingress egress; do
				echo "  $direction:"
				tc filter show dev "$interface_name" "$direction" 2>/dev/null | sed 's/^/    /' || true
			done
		else
			echo "TC filters: interface $interface_name is absent or tc is unavailable."
		fi
	elif [ "$mode" = all ] || [ "$mode" = shared-network ]; then
		echo "TC filters: pass --interface to inspect the configured downstream interface."
	fi
}

echo "sing-box eBPF inbound kernel capability probe"
echo "Platform: $platform; kernel: $kernel_release; architecture: $machine; mode: $mode"
if [ -n "$kernel_config_source" ]; then
	echo "Kernel configuration: $kernel_config_source"
else
	echo "Kernel configuration: unavailable"
fi
if [ "$bpftool_probed" -eq 1 ]; then
	echo "Runtime feature probe: bpftool"
elif has_command bpftool; then
	echo "Runtime feature probe: bpftool failed ($(sed -n '1p' "$bpftool_error" 2>/dev/null))"
else
	echo "Runtime feature probe: bpftool not installed; using conservative fallbacks"
fi
echo

if [ "$(id -u 2>/dev/null || echo 1)" = 0 ]; then
	report PASS common required "privileged process" "The process can normally create BPF maps/programs and manage cgroup, TC, routes, and sysctls."
else
	report UNKNOWN common required "BPF and network administration privileges" "Run as root, or provide effective CAP_BPF/CAP_SYS_ADMIN, CAP_NET_ADMIN, and resource-limit permissions."
fi

check_config common required BPF "Provides the in-kernel BPF infrastructure used by every data path."
check_config common required BPF_SYSCALL "Allows sing-box to create maps and load programs through bpf(2)."

if [ "$bpftool_probed" -eq 1 ]; then
	if bpftool_has 'bpf() syscall is available'; then
		report PASS common required "bpf(2) syscall" "The running kernel accepted bpftool BPF feature probes."
	else
		report FAIL common required "bpf(2) syscall" "Without bpf(2), no eBPF inbound data path can start."
	fi
else
	report UNKNOWN common required "bpf(2) syscall runtime access" "CONFIG_BPF_SYSCALL is only a build-time indication; seccomp, capabilities, or an LSM can still deny access."
fi

check_config common performance BPF_JIT "JIT compilation avoids interpreting eBPF instructions and is strongly recommended for throughput and packet rate."

memlock=$(ulimit -l 2>/dev/null || echo unknown)
case "$memlock" in
	unlimited|unlimited\ *)
		report PASS common required "locked-memory limit" "The process may lock enough memory for configured BPF maps."
		;;
	unknown)
		report UNKNOWN common required "locked-memory limit" "sing-box raises RLIMIT_MEMLOCK at startup; the limit could not be read here."
		;;
	*)
		if (ulimit -l unlimited) 2>/dev/null; then
			report PASS common required "locked-memory limit can be raised (current: $memlock)" "A temporary child shell successfully raised RLIMIT_MEMLOCK to unlimited, matching sing-box startup behavior."
		else
			report WARN common required "locked-memory limit: $memlock" "sing-box raises RLIMIT_MEMLOCK at startup. Containers, Android services, or procd jails must allow the raise, or large maps can fail with EPERM/ENOMEM."
		fi
		;;
esac

check_map_type common required hash "Stores TCP/UDP redirect state and shared-network flow state."
check_map_type common required lru_hash "Stores socket protection and bounded UDP/shared-network caches."
check_map_type common required lpm_trie "Stores local-interface, UID, rule-set CIDR, and shared-network host/bypass policies."

if [ "$mode" = all ] || [ "$mode" = local ]; then
	echo
	echo "Local cgroup data path"
	check_config local required CGROUPS "Provides the cgroup hierarchy used to select locally generated traffic."
	check_config local required CGROUP_BPF "Allows BPF programs to be attached to a cgroup."

	cgroup2_mount=$(awk '$3 == "cgroup2" { print $2; exit }' /proc/mounts 2>/dev/null)
	if [ -z "$cgroup_path" ]; then
		cgroup_path=$cgroup2_mount
	fi
	case "$cgroup_path" in
		"$cgroup2_mount"|"$cgroup2_mount"/*)
			if [ -n "$cgroup2_mount" ] && [ -d "$cgroup_path" ]; then
				report PASS local required "cgroup v2 path: $cgroup_path" "connect/sendmsg/recvmsg programs attach to this hierarchy."
			else
				report FAIL local required "cgroup v2 mount/path" "The configured cgroup v2 path does not exist."
			fi
			;;
		*)
			report FAIL local required "cgroup v2 mount/path" "$cgroup_path is not below the detected cgroup v2 mount $cgroup2_mount."
			;;
	esac

	check_program_type local required cgroup_sock_addr "Implements TCP connect interception, UDP sendmsg interception, and UDP recvmsg source restoration."
	check_helper local required cgroup_sock_addr map_lookup_elem "Reads UID/CIDR policy, protected socket cookies, and redirect state."
	check_helper local required cgroup_sock_addr map_update_elem "Creates redirect, token, peer, and flow-cache state."
	check_helper local required cgroup_sock_addr map_delete_elem "Reclaims or replaces UDP state."
	check_helper local required cgroup_sock_addr get_socket_cookie "Identifies UDP sockets and provides the cookie self-protection fallback."
	if [ "$platform" = Android ]; then
		check_helper local required cgroup_sock_addr get_current_uid_gid "Enforces UID policy, including the mandatory Android dns_tether exclusion."
	else
		check_helper local fallback cgroup_sock_addr get_current_uid_gid "Required only when include_uid or exclude_uid policy is configured."
	fi
	check_helper local performance cgroup_sock_addr get_current_pid_tgid "Provides the fast sing-box self-bypass path; absence falls back to socket-cookie lookup."

	report UNKNOWN local required "cgroup attach types: connect4/connect6" "Required for TCP and for IPv4-mapped IPv6 sockets. bpftool cannot safely distinguish cgroup_sock_addr attach subtypes; sing-box startup performs the definitive verifier/load check."
	report UNKNOWN local required "cgroup attach types: UDP4/UDP6 sendmsg and recvmsg" "Required when UDP is enabled. sendmsg redirects packets and recvmsg restores the original peer address; sing-box startup is the definitive check."

	check_program_type local fallback cgroup_sock "Enables the optional inet_sock_release hook for exact connected-UDP cleanup."
	check_helper local fallback cgroup_sock get_socket_cookie "Lets inet_sock_release find and delete state owned by the closing UDP socket."
	report UNKNOWN local fallback "BPF_CGROUP_INET_SOCK_RELEASE attach type" "When unsupported, sing-box automatically uses bounded LRU compatibility maps and disables the unconnected-UDP flow cache."

	report UNKNOWN local performance "BPF_MAP_LOOKUP_AND_DELETE_ELEM" "bpftool does not expose a safe HASH-map probe for this syscall command. sing-box detects it while reading a TCP original destination and falls back to separate lookup and delete calls, including Android private ENOTSUPP."
fi

if [ "$mode" = all ] || [ "$mode" = shared-network ]; then
	echo
	echo "Shared-network TC gateway data path"
	check_config shared-network required NET_SCHED "Provides Linux traffic-control qdiscs and filters."
	check_config shared-network required NET_SCH_INGRESS "Provides the clsact/ingress qdisc used on every selected downstream interface."
	check_config shared-network required NET_CLS_ACT "Allows direct-action classifier programs to return TC actions."
	check_config shared-network required NET_CLS_BPF "Allows sched_cls eBPF programs to run at TC ingress and egress."
	check_program_type shared-network required sched_cls "Implements token rewrite, reply restoration, DNS hijack, DHCP bypass, and CIDR bypass for forwarded packets."
	check_map_type shared-network required array "Stores shared-network runtime control flags and listener information."
	check_map_type shared-network required percpu_array "Provides per-CPU packet parsing scratch space without a global lock."
	check_helper shared-network required sched_cls map_lookup_elem "Reads control, host/bypass policy, and flow state."
	check_helper shared-network required sched_cls map_update_elem "Creates forward, reply, listener, and bypass-flow state."
	check_helper shared-network required sched_cls map_delete_elem "Removes expired or completed TC flow state."
	check_helper shared-network required sched_cls ktime_get_ns "Applies UDP/TCP flow lifetimes and bypass-decision cache timeouts."
	check_helper shared-network required sched_cls skb_pull_data "Makes the packet headers linear and writable before parsing or rewriting."
	check_helper shared-network required sched_cls skb_store_bytes "Rewrites token/original IP addresses and ports in forwarded packets."
	check_helper shared-network required sched_cls csum_diff "Calculates address checksum deltas for IPv4/IPv6 packet rewrites."
	check_helper shared-network required sched_cls l3_csum_replace "Updates the IPv4 header checksum after rewriting an address."
	check_helper shared-network required sched_cls l4_csum_replace "Updates TCP/UDP checksums after rewriting addresses or ports."

	if [ -n "$interface_name" ]; then
		if [ ! -d "/sys/class/net/$interface_name" ]; then
			report FAIL shared-network required "interface $interface_name" "The interface is absent. Android hotspot interfaces may legitimately appear only while the hotspot is enabled."
		else
			interface_type=$(cat "/sys/class/net/$interface_name/type" 2>/dev/null || echo unknown)
			if [ "$interface_type" = 1 ]; then
				report PASS shared-network required "Ethernet-like interface $interface_name" "TC token rewriting expects Ethernet headers, including Ethernet-emulated Android Wi-Fi interfaces."
			else
				report WARN shared-network required "interface $interface_name type $interface_type" "The shared-network parser expects Ethernet-like frames; validate this driver and link type on-device."
			fi
			route_localnet="/proc/sys/net/ipv4/conf/$interface_name/route_localnet"
			if [ -e "$route_localnet" ] && [ -w "$route_localnet" ]; then
				report PASS shared-network required "writable route_localnet for $interface_name" "Required for IPv4 token addresses to be routed to the local shared listener."
			else
				report FAIL shared-network required "writable route_localnet for $interface_name" "IPv4 shared-network cannot redirect token addresses locally without this per-interface sysctl."
			fi
		fi
	else
		report UNKNOWN shared-network required "downstream interface and route_localnet" "Pass --interface with the configured include_interface to verify Ethernet framing and the IPv4 sysctl path."
	fi
	report UNKNOWN shared-network required "TC ingress and egress attachment" "The script deliberately does not create a qdisc or filter. sing-box startup is the definitive attachment test; hardware/XDP offload can still bypass an attached TC hook."
fi

show_active_state

echo
echo "Summary: PASS=$pass_count WARN=$warn_count FAIL=$fail_count UNKNOWN=$unknown_count"
if [ "$required_fail_count" -gt 0 ]; then
	echo "Result: unsupported for at least one selected data path ($required_fail_count required check(s) failed)."
	exit 1
fi
if [ "$unknown_count" -gt 0 ]; then
	echo "Result: no required failure was proven, but UNKNOWN items need bpftool, an interface argument, or a real sing-box startup check."
else
	echo "Result: all selected checks passed or have a documented compatible fallback."
fi
exit 0
