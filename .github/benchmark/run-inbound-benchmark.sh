#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run-inbound-benchmark.sh --sing-box PATH --benchmark PATH --output DIR [options]

Options:
  --debug-sing-box PATH     ebpf_debug sing-box binary used only for profiling
  --duration DURATION       Measurement duration per scenario (default: 5s)
  --warmup DURATION         Warm-up duration per scenario (default: 1s)
  --repetitions COUNT       Repetitions per inbound (default: 3)
  --concurrency COUNT       Parallel connections or UDP flows (default: 16)
  --tcp-payload-size BYTES  TCP upload frame size (default: 32768)
  --udp-payload-size BYTES  UDP datagram size (default: 1200)
  --family FAMILY           Address family: ipv4 or ipv6 (default: ipv4)
  --ebpf-policy-prefixes N  Non-matching bypass CIDRs for eBPF stress (default: 0)
  --variants LIST           Comma-separated inbound variants (default: full matrix)
  --scenarios LIST          Benchmark scenarios passed to the client (default: all)
  --profile-seconds COUNT   Connected UDP profile duration in seconds (default: 0)
EOF
}

sing_box=
debug_sing_box=
benchmark=
output=
duration=5s
warmup=1s
repetitions=3
concurrency=16
tcp_payload_size=32768
udp_payload_size=1200
family=ipv4
ebpf_policy_prefixes=0
variants=direct,ebpf-local,ebpf-shared,redirect,tproxy,tun-mixed,tun-mixed-auto-redirect
scenarios=all
profile_seconds=0

while (($# > 0)); do
  case "$1" in
    --sing-box)
      sing_box=$2
      shift 2
      ;;
    --debug-sing-box)
      debug_sing_box=$2
      shift 2
      ;;
    --benchmark)
      benchmark=$2
      shift 2
      ;;
    --output)
      output=$2
      shift 2
      ;;
    --duration)
      duration=$2
      shift 2
      ;;
    --warmup)
      warmup=$2
      shift 2
      ;;
    --repetitions)
      repetitions=$2
      shift 2
      ;;
    --concurrency)
      concurrency=$2
      shift 2
      ;;
    --tcp-payload-size)
      tcp_payload_size=$2
      shift 2
      ;;
    --udp-payload-size)
      udp_payload_size=$2
      shift 2
      ;;
    --family)
      family=$2
      shift 2
      ;;
    --ebpf-policy-prefixes)
      ebpf_policy_prefixes=$2
      shift 2
      ;;
    --variants)
      variants=$2
      shift 2
      ;;
    --scenarios)
      scenarios=$2
      shift 2
      ;;
    --profile-seconds)
      profile_seconds=$2
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

if [[ -z $sing_box || -z $benchmark || -z $output ]]; then
  usage >&2
  exit 2
fi
if [[ $EUID -ne 0 ]]; then
  echo "the benchmark network topology requires root" >&2
  exit 1
fi
if [[ ! -x $sing_box || ! -x $benchmark ]]; then
  echo "sing-box and benchmark paths must be executable" >&2
  exit 1
fi
if [[ ! $repetitions =~ ^[1-9][0-9]*$ || ! $concurrency =~ ^[1-9][0-9]*$ ]]; then
  echo "repetitions and concurrency must be positive integers" >&2
  exit 2
fi
if [[ ! $tcp_payload_size =~ ^[1-9][0-9]*$ || $tcp_payload_size -gt 1048576 ]]; then
  echo "tcp-payload-size must be between 1 and 1048576" >&2
  exit 2
fi
if [[ ! $udp_payload_size =~ ^[1-9][0-9]*$ || $udp_payload_size -gt 65507 ]]; then
  echo "udp-payload-size must be between 1 and 65507" >&2
  exit 2
fi
if [[ $family != ipv4 && $family != ipv6 ]]; then
  echo "family must be ipv4 or ipv6" >&2
  exit 2
fi
if [[ ! $ebpf_policy_prefixes =~ ^[0-9]+$ || $ebpf_policy_prefixes -gt 32768 ]]; then
  echo "ebpf-policy-prefixes must be between 0 and 32768" >&2
  exit 2
fi
if ((repetitions > 1000)); then
  echo "repetitions must not exceed 1000" >&2
  exit 2
fi
IFS=',' read -r -a benchmark_variants <<< "$variants"
if ((${#benchmark_variants[@]} == 0)); then
  echo "at least one benchmark variant is required" >&2
  exit 2
fi
declare -A seen_variants=()
for variant in "${benchmark_variants[@]}"; do
  case "$variant" in
    direct|ebpf-local|ebpf-shared|redirect|tproxy|tun-mixed|tun-mixed-auto-redirect) ;;
    *)
      echo "unknown benchmark variant: $variant" >&2
      exit 2
      ;;
  esac
  if [[ -n ${seen_variants[$variant]:-} ]]; then
    echo "duplicate benchmark variant: $variant" >&2
    exit 2
  fi
  seen_variants[$variant]=1
done
if [[ ! $profile_seconds =~ ^[0-9]+$ || $profile_seconds -gt 300 ]]; then
  echo "profile-seconds must be between 0 and 300" >&2
  exit 2
fi
required_commands=(ip jq mountpoint ping python3 realpath setpriv shuf ss sysctl)
if [[ $family == ipv4 ]]; then
  required_commands+=(iptables)
else
  required_commands+=(ip6tables)
fi
for command in "${required_commands[@]}"; do
  if ! command -v "$command" >/dev/null; then
    echo "missing command: $command" >&2
    exit 1
  fi
done
if ((profile_seconds > 0)); then
  for command in curl go; do
    if ! command -v "$command" >/dev/null; then
      echo "missing command: $command" >&2
      exit 1
    fi
  done
  if [[ -z $debug_sing_box ]]; then
    debug_sing_box=$sing_box
  fi
  debug_sing_box=$(realpath "$debug_sing_box")
  if [[ ! -x $debug_sing_box ]]; then
    echo "debug sing-box binary is not executable: $debug_sing_box" >&2
    exit 1
  fi
fi

sing_box=$(realpath "$sing_box")
benchmark=$(realpath "$benchmark")
output=$(realpath -m "$output")
if [[ -d $output ]] && find "$output" -mindepth 1 -print -quit | grep -q .; then
  echo "output directory is not empty: $output" >&2
  exit 1
fi
mkdir -p "$output"/{config,environment,logs,profiles,raw,validation}

run_token="${GITHUB_RUN_ID:-local}-$$"
app_namespace="sb-bench-app-$run_token"
router_namespace="sb-bench-router-$run_token"
server_namespace="sb-bench-server-$run_token"
app_interface="sba$$"
router_app_interface="sbra$$"
router_server_interface="sbrs$$"
server_interface="sbs$$"
cgroup_path="/sys/fs/cgroup/sing-box-benchmark-$run_token"
if [[ $family == ipv4 ]]; then
  app_address=10.89.0.2
  router_app_address=10.89.0.1
  router_server_address=10.89.1.1
  server_address=10.89.1.2
  server_target=$server_address
  app_prefix=24
  server_prefix=24
  server_route_prefix=32
  tun_address=172.19.0.1/30
  tun_route_prefix=32
  listen_address=0.0.0.0
  local_route=0.0.0.0/0
  firewall=iptables
  ip_family=()
  ping_family=()
  address_flags=()
  local_ipv6=false
  shared_ipv6=false
else
  app_address=fd89::2
  router_app_address=fd89::1
  router_server_address=fd89:1::1
  server_address=fd89:1::2
  server_target="[$server_address]"
  app_prefix=64
  server_prefix=64
  server_route_prefix=128
  tun_address=fd89:19::1/126
  tun_route_prefix=128
  listen_address=::
  local_route=::/0
  firewall=ip6tables
  ip_family=(-6)
  ping_family=(-6)
  address_flags=(nodad)
  local_ipv6=true
  shared_ipv6=true
fi
server_port=
redirect_port=15001
tproxy_port=15002
sing_box_pid=
server_pid=
profile_pid=
failed=0
policy_rule_sets='[]'

stop_sing_box() {
  if [[ -n ${sing_box_pid:-} ]]; then
    kill "$sing_box_pid" 2>/dev/null || true
    wait "$sing_box_pid" 2>/dev/null || true
    sing_box_pid=
  fi
}

stop_server() {
  if [[ -n ${server_pid:-} ]]; then
    kill "$server_pid" 2>/dev/null || true
    wait "$server_pid" 2>/dev/null || true
    server_pid=
  fi
}

stop_profile() {
  if [[ -n ${profile_pid:-} ]]; then
    kill "$profile_pid" 2>/dev/null || true
    wait "$profile_pid" 2>/dev/null || true
    profile_pid=
  fi
}

cleanup() {
  set +e
  stop_profile
  stop_sing_box
  stop_server
  ip netns delete "$app_namespace" 2>/dev/null
  ip netns delete "$router_namespace" 2>/dev/null
  ip netns delete "$server_namespace" 2>/dev/null
  if [[ $cgroup_path == /sys/fs/cgroup/sing-box-benchmark-* ]]; then
    rmdir "$cgroup_path" 2>/dev/null
  fi
  if [[ -n ${SUDO_UID:-} && -n ${SUDO_GID:-} ]]; then
    chown -R "$SUDO_UID:$SUDO_GID" "$output"
  fi
}
trap cleanup EXIT INT TERM

record_environment() {
  {
    echo "commit=${SING_BOX_BENCHMARK_COMMIT:-$(git rev-parse HEAD 2>/dev/null || true)}"
    echo "date=$(date --iso-8601=seconds)"
    echo "duration=$duration"
    echo "warmup=$warmup"
    echo "repetitions=$repetitions"
    echo "concurrency=$concurrency"
    echo "tcp_payload_size=$tcp_payload_size"
    echo "udp_payload_size=$udp_payload_size"
    echo "family=$family"
    echo "ebpf_policy_prefixes=$ebpf_policy_prefixes"
    echo "variants=$variants"
    echo "scenarios=$scenarios"
    echo "profile_seconds=$profile_seconds"
    echo "sing_box=$($sing_box version 2>&1 | head -n 1)"
    if [[ -n $debug_sing_box ]]; then
      echo "debug_sing_box=$($debug_sing_box version 2>&1 | head -n 1)"
    fi
  } > "$output/environment/run.txt"
  uname -a > "$output/environment/uname.txt"
  lscpu > "$output/environment/lscpu.txt" 2>&1 || true
  mount | grep cgroup > "$output/environment/cgroup-mounts.txt" || true
  sysctl kernel.unprivileged_bpf_disabled > "$output/environment/bpf.txt" 2>&1 || true
  ip -details link show > "$output/environment/links.txt"
}

prepare_policy_rule_set() {
  if ((ebpf_policy_prefixes == 0)); then
    return
  fi
  python3 - "$family" "$ebpf_policy_prefixes" \
    > "$output/config/policy-prefixes.json" <<'PY'
import ipaddress
import json
import sys

family = sys.argv[1]
count = int(sys.argv[2])
base = ipaddress.ip_address("198.18.0.0" if family == "ipv4" else "fd00:beef::")
bits = 32 if family == "ipv4" else 128
print(json.dumps([f"{base + index * 2}/{bits}" for index in range(count)]))
PY
  policy_rule_sets=$(jq -c '{
    type: "inline",
    tag: "benchmark-policy",
    rules: [{ip_cidr: .}]
  } | [.]' "$output/config/policy-prefixes.json")
}

create_topology() {
  ip netns add "$app_namespace"
  ip netns add "$router_namespace"
  ip netns add "$server_namespace"

  ip link add "$app_interface" type veth peer name "$router_app_interface"
  ip link set "$app_interface" netns "$app_namespace"
  ip link set "$router_app_interface" netns "$router_namespace"
  ip link add "$router_server_interface" type veth peer name "$server_interface"
  ip link set "$router_server_interface" netns "$router_namespace"
  ip link set "$server_interface" netns "$server_namespace"

  ip -n "$app_namespace" link set lo up
  ip "${ip_family[@]}" -n "$app_namespace" address add "$app_address/$app_prefix" dev "$app_interface" "${address_flags[@]}"
  ip -n "$app_namespace" link set "$app_interface" up
  ip "${ip_family[@]}" -n "$app_namespace" route add default via "$router_app_address"

  ip -n "$router_namespace" link set lo up
  ip "${ip_family[@]}" -n "$router_namespace" address add "$router_app_address/$app_prefix" dev "$router_app_interface" "${address_flags[@]}"
  ip "${ip_family[@]}" -n "$router_namespace" address add "$router_server_address/$server_prefix" dev "$router_server_interface" "${address_flags[@]}"
  ip -n "$router_namespace" link set "$router_app_interface" up
  ip -n "$router_namespace" link set "$router_server_interface" up
  ip "${ip_family[@]}" -n "$router_namespace" route add default via "$server_address"
  if [[ $family == ipv4 ]]; then
    ip netns exec "$router_namespace" sysctl -q -w net.ipv4.ip_forward=1
  else
    ip netns exec "$router_namespace" sysctl -q -w net.ipv6.conf.all.forwarding=1
  fi
  ip netns exec "$router_namespace" "$firewall" -P FORWARD ACCEPT

  ip -n "$server_namespace" link set lo up
  ip "${ip_family[@]}" -n "$server_namespace" address add "$server_address/$server_prefix" dev "$server_interface" "${address_flags[@]}"
  ip -n "$server_namespace" link set "$server_interface" up
  ip "${ip_family[@]}" -n "$server_namespace" route add "$app_address/$server_route_prefix" via "$router_server_address"

  mkdir "$cgroup_path"
  # Multiple probes let IPv6 neighbor discovery settle before the first measured flow.
  ip netns exec "$app_namespace" ping "${ping_family[@]}" -c 3 -W 2 "$server_address" >/dev/null

  {
    for namespace in "$app_namespace" "$router_namespace" "$server_namespace"; do
      echo "### $namespace"
      ip -n "$namespace" -details address show
      ip "${ip_family[@]}" -n "$namespace" route show table all
    done
  } > "$output/environment/topology.txt"
  for pair in "$app_namespace:$app_interface" \
    "$router_namespace:$router_app_interface" \
    "$router_namespace:$router_server_interface" \
    "$server_namespace:$server_interface"; do
    namespace=${pair%%:*}
    interface=${pair#*:}
    {
      echo "### $namespace/$interface"
      ip netns exec "$namespace" ethtool -k "$interface" 2>&1 || true
    } >> "$output/environment/offloads.txt"
  done
}

start_server() {
  local variant=$1
  local repetition=$2
  ip netns exec "$server_namespace" "$benchmark" \
    -mode server -listen ":$server_port" \
    > "$output/logs/server-$variant-$repetition.log" 2>&1 &
  server_pid=$!
  for _ in $(seq 1 30); do
    if ! kill -0 "$server_pid" 2>/dev/null; then
      echo "benchmark server exited during startup" >&2
      return 1
    fi
    if ip netns exec "$server_namespace" ss -H -ltn "sport = :$server_port" | grep -q .; then
      return 0
    fi
    sleep 0.1
  done
  echo "benchmark server did not become ready" >&2
  return 1
}

write_common_config() {
  local inbound=$1
  local config=$2
  local debug_listen=${3:-}
  local log_level=${4:-error}
  jq -n \
    --argjson inbound "$inbound" \
    --argjson rule_sets "$policy_rule_sets" \
    --arg debug_listen "$debug_listen" \
    --arg log_level "$log_level" '{
    log: {level: $log_level, timestamp: true},
    inbounds: [$inbound],
    outbounds: [{type: "direct", tag: "direct"}],
    route: ({final: "direct"} + if ($rule_sets | length) == 0 then {} else {rule_set: $rule_sets} end)
  } + if $debug_listen == "" then {} else {
    experimental: {debug: {listen: $debug_listen}}
  } end' > "$config"
}

start_sing_box() {
  local variant=$1
  local repetition=$2
  local config="$output/config/$variant-$repetition.json"
  local log="$output/logs/$variant-$repetition.log"
  local namespace=$router_namespace
  local debug_listen=
  local log_level=error
  local runtime_binary=$sing_box
  local inbound

  case "$variant" in
    ebpf-local|ebpf-profile-local)
      namespace=$app_namespace
      if [[ $variant == ebpf-profile-local ]]; then
        debug_listen=127.0.0.1:6060
        log_level=debug
        runtime_binary=$debug_sing_box
      fi
      inbound=$(jq -n --arg cgroup "$cgroup_path" --argjson ipv6 "$local_ipv6" '{
        type: "ebpf",
        tag: "benchmark-in",
        mode: "local",
        network: ["tcp", "udp"],
        local: {
          dns_mode: "off",
          cgroup_path: $cgroup,
          ipv6: $ipv6,
          bypass_private_address: false
        }
      }')
      ;;
    ebpf-shared|ebpf-shared-leak-check|ebpf-profile-shared)
      if [[ $variant == ebpf-profile-shared ]]; then
        debug_listen=127.0.0.1:6060
        log_level=debug
        runtime_binary=$debug_sing_box
      fi
      inbound=$(jq -n --arg interface "$router_app_interface" --argjson ipv6 "$shared_ipv6" '{
        type: "ebpf",
        tag: "benchmark-in",
        mode: "shared",
        network: ["tcp", "udp"],
        shared: {
          dns_mode: "off",
          interface: [$interface],
          ipv6: $ipv6,
          bypass_private_address: false
        }
      }')
      ;;
    redirect)
      inbound=$(jq -n --arg listen "$listen_address" --argjson port "$redirect_port" '{
        type: "redirect",
        tag: "benchmark-in",
        listen: $listen,
        listen_port: $port
      }')
      ip netns exec "$router_namespace" "$firewall" -t nat -A PREROUTING \
        -s "$app_address" -d "$server_address" -p tcp --dport "$server_port" \
        -j REDIRECT --to-ports "$redirect_port"
      ;;
    tproxy)
      inbound=$(jq -n --arg listen "$listen_address" --argjson port "$tproxy_port" '{
        type: "tproxy",
        tag: "benchmark-in",
        listen: $listen,
        listen_port: $port,
        network: ["tcp", "udp"]
      }')
      ip netns exec "$router_namespace" ip "${ip_family[@]}" rule add fwmark 1 table 100
      ip netns exec "$router_namespace" ip "${ip_family[@]}" route add local "$local_route" dev lo table 100
      for network in tcp udp; do
        ip netns exec "$router_namespace" "$firewall" -t mangle -A PREROUTING \
          -s "$app_address" -d "$server_address" -p "$network" --dport "$server_port" \
          -j TPROXY --on-ip "$listen_address" --on-port "$tproxy_port" --tproxy-mark 0x1/0x1
      done
      ;;
    tun-mixed|tun-mixed-auto-redirect)
      namespace=$app_namespace
      local auto_redirect=false
      if [[ $variant == *-auto-redirect ]]; then
        auto_redirect=true
      fi
      inbound=$(jq -n \
        --arg server "$server_address/$tun_route_prefix" \
        --arg tunAddress "$tun_address" \
        --argjson autoRedirect "$auto_redirect" \
        '{
        type: "tun",
        tag: "benchmark-in",
        interface_name: "sb-benchmark",
        address: $tunAddress,
        mtu: 1500,
        auto_route: true,
        auto_redirect: $autoRedirect,
        stack: "mixed",
        route_address: [$server],
        exclude_uid: [0]
      }')
      ;;
    *)
      echo "unknown variant: $variant" >&2
      return 1
      ;;
  esac

  if ((ebpf_policy_prefixes > 0)) && [[ $variant == ebpf-* ]]; then
    inbound=$(jq -c '. + {bypass_rule_set: ["benchmark-policy"]}' <<< "$inbound")
  fi
  write_common_config "$inbound" "$config" "$debug_listen" "$log_level"
  if [[ $variant == ebpf-local || $variant == ebpf-profile-local ]]; then
    ip netns exec "$namespace" bash -c '
      if ! mountpoint -q /sys/fs/cgroup; then
        mount -t cgroup2 none /sys/fs/cgroup
      fi
      exec "$@"
    ' benchmark-ebpf "$runtime_binary" run -c "$config" > "$log" 2>&1 &
  else
    ip netns exec "$namespace" "$runtime_binary" run -c "$config" > "$log" 2>&1 &
  fi
  sing_box_pid=$!
  for _ in $(seq 1 30); do
    if ! kill -0 "$sing_box_pid" 2>/dev/null; then
      echo "$variant failed to start; see $log" >&2
      return 1
    fi
    sleep 0.1
  done
}

reset_router_rules() {
  ip netns exec "$router_namespace" "$firewall" -t nat -F
  ip netns exec "$router_namespace" "$firewall" -t mangle -F
  ip netns exec "$app_namespace" "$firewall" -t filter -F OUTPUT
  ip netns exec "$router_namespace" "$firewall" -t filter -F FORWARD
  ip netns exec "$router_namespace" ip "${ip_family[@]}" rule del fwmark 1 table 100 2>/dev/null || true
  ip netns exec "$router_namespace" ip "${ip_family[@]}" route flush table 100 2>/dev/null || true
}

run_forwarded_leak_check() {
  local variant=$1
  local repetition=validation
  local result=0
  local validation_scenarios=tcp-short,udp-pps,udp-unconnected-pps,udp-churn
  if [[ $variant == redirect ]]; then
    validation_scenarios=tcp-short
  fi
  server_port=20993
  reset_router_rules
  start_server "$variant" "$repetition" || result=$?
  if [[ $result -eq 0 ]]; then
    start_sing_box "$variant" "$repetition" || result=$?
  fi
  if [[ $result -eq 0 ]]; then
    for network in tcp udp; do
      ip netns exec "$router_namespace" "$firewall" -t filter -I FORWARD \
        -s "$app_address" -d "$server_address" -p "$network" --dport "$server_port" \
        -j REJECT || result=$?
    done
  fi
  if [[ $result -eq 0 ]]; then
    run_benchmark_client "$variant" "$validation_scenarios" 1s 0s \
      "$output/validation/$variant-no-direct-leak.json" || result=$?
  fi
  stop_sing_box
  stop_server
  reset_router_rules
  if [[ $result -ne 0 ]]; then
    printf '%s\t%s\t%s\n' "$variant-leak-check" "$repetition" "$result" \
      >> "$output/failures.tsv"
    failed=1
  fi
}

run_local_leak_check() {
  local variant=$1
  local repetition=validation
  local result=0
  local client_uid=65534
  server_port=20991
  reset_router_rules
  start_server "$variant" "$repetition" || result=$?
  if [[ $result -eq 0 ]]; then
    start_sing_box "$variant" "$repetition" || result=$?
  fi
  if [[ $result -eq 0 ]]; then
    for network in tcp udp; do
      ip netns exec "$app_namespace" "$firewall" -t filter -A OUTPUT \
        -m owner --uid-owner "$client_uid" \
        -d "$server_address" -p "$network" --dport "$server_port" \
        -j REJECT || result=$?
    done
  fi
  if [[ $result -eq 0 ]]; then
    run_benchmark_client "$variant" tcp-short,udp-pps,udp-unconnected-pps,udp-churn \
      1s 0s "$output/validation/$variant-no-direct-leak.json" "$client_uid" || result=$?
  fi
  stop_sing_box
  stop_server
  reset_router_rules
  if [[ $result -ne 0 ]]; then
    printf '%s\t%s\t%s\n' "$variant-leak-check" "$repetition" "$result" \
      >> "$output/failures.tsv"
    failed=1
  fi
}

run_client() {
  local variant=$1
  local repetition=$2
  local client_scenarios=$scenarios
  local raw="$output/raw/$variant/$repetition.json"
  if [[ $variant == redirect ]]; then
    client_scenarios=$(redirect_scenarios "$client_scenarios")
  fi

  run_benchmark_client "$variant" "$client_scenarios" "$duration" "$warmup" "$raw"
}

record_process_metrics() {
  local variant=$1
  local repetition=$2
  local destination="$output/raw/$variant/$repetition-process.txt"
  if [[ -z ${sing_box_pid:-} || ! -r /proc/$sing_box_pid/status ]]; then
    return
  fi
  {
    echo "pid=$sing_box_pid"
    awk '{ print "cpu_ticks=" $14 + $15 }' "/proc/$sing_box_pid/stat"
    grep -E '^(VmPeak|VmHWM|VmRSS|Threads|voluntary_ctxt_switches|nonvoluntary_ctxt_switches):' \
      "/proc/$sing_box_pid/status"
  } > "$destination"
}

record_tun_activity() {
  local variant=$1
  local repetition=$2
  local destination="$output/raw/$variant/$repetition-tun.txt"
  local receive_packets
  local transmit_packets
  receive_packets=$(ip netns exec "$app_namespace" \
    cat /sys/class/net/sb-benchmark/statistics/rx_packets)
  transmit_packets=$(ip netns exec "$app_namespace" \
    cat /sys/class/net/sb-benchmark/statistics/tx_packets)
  {
    echo "rx_packets=$receive_packets"
    echo "tx_packets=$transmit_packets"
  } > "$destination"
  ((receive_packets + transmit_packets > 0))
}

redirect_scenarios() {
  local requested=$1
  if [[ $requested == all ]]; then
    printf '%s\n' tcp-short,tcp-upload,tcp-download
    return
  fi
  local selected=()
  local scenario
  IFS=',' read -r -a requested_scenarios <<< "$requested"
  for scenario in "${requested_scenarios[@]}"; do
    case "$scenario" in
      udp-pps|udp-unconnected-pps|udp-churn) ;;
      *) selected+=("$scenario") ;;
    esac
  done
  if ((${#selected[@]} == 0)); then
    echo "redirect has no applicable requested scenarios" >&2
    return 1
  fi
  local joined
  printf -v joined '%s,' "${selected[@]}"
  printf '%s\n' "${joined%,}"
}

run_benchmark_client() {
  local variant=$1
  local scenarios=$2
  local client_duration=$3
  local client_warmup=$4
  local raw=$5
  local client_uid=${6:-65534}
  mkdir -p "$(dirname "$raw")"

  local command=(
    "$benchmark"
    -mode client
    -target "$server_target:$server_port"
    -scenario "$scenarios"
    -duration "$client_duration"
    -warmup "$client_warmup"
    -concurrency "$concurrency"
    -tcp-payload-size "$tcp_payload_size"
    -udp-payload-size "$udp_payload_size"
  )
  local namespace_command=("${command[@]}")
  if [[ -n $client_uid ]]; then
    namespace_command=(
      setpriv
      "--reuid=$client_uid"
      "--regid=$client_uid"
      --clear-groups
      "${command[@]}"
    )
  fi
  if [[ $variant == ebpf-local || $variant == ebpf-profile-local ]]; then
    bash -c 'echo $$ > "$1/cgroup.procs"; shift; exec ip netns exec "$@"' \
      benchmark-cgroup "$cgroup_path" "$app_namespace" "${namespace_command[@]}" > "$raw"
  else
    ip netns exec "$app_namespace" "${namespace_command[@]}" > "$raw"
  fi
  jq -e '.results | length > 0 and all(.errors == 0 and .rate > 0)' "$raw" >/dev/null
}

run_ebpf_udp_profile() {
  local mode=$1
  local variant=ebpf-profile-$mode
  local repetition=1
  local result=0
  local profile_dir="$output/profiles/$mode"
  local profile_namespace=$app_namespace
  if [[ $mode == shared ]]; then
    profile_namespace=$router_namespace
  fi
  mkdir -p "$profile_dir"
  server_port=20992
  reset_router_rules
  start_server "$variant" "$repetition" || result=$?
  if [[ $result -eq 0 ]]; then
    start_sing_box "$variant" "$repetition" || result=$?
  fi
  if [[ $result -eq 0 ]]; then
    local profile_ready=false
    for _ in $(seq 1 30); do
      if ip netns exec "$profile_namespace" curl --fail --silent --output /dev/null \
        http://127.0.0.1:6060/debug/pprof/; then
        profile_ready=true
        break
      fi
      sleep 0.1
    done
    if [[ $profile_ready != true ]]; then
      echo "$variant debug endpoint did not become ready" >&2
      result=1
    else
      run_benchmark_client "$variant" udp-pps 1s 0s \
        "$profile_dir/udp-connected-warmup.json" || result=$?
    fi
  fi
  if [[ $result -eq 0 ]]; then
    ip netns exec "$profile_namespace" curl --fail --silent --show-error \
      --output "$profile_dir/udp-connected-cpu.pprof" \
      "http://127.0.0.1:6060/debug/pprof/profile?seconds=$profile_seconds" &
    profile_pid=$!
    sleep 0.2
    run_benchmark_client "$variant" udp-pps "${profile_seconds}s" 0s \
      "$profile_dir/udp-connected-cpu-load.json" || result=$?
    wait "$profile_pid" || result=$?
    profile_pid=
  fi
  if [[ $result -eq 0 ]]; then
    for profile in allocs heap; do
      ip netns exec "$profile_namespace" curl --fail --silent --show-error \
        --output "$profile_dir/udp-connected-$profile-before.pprof" \
        "http://127.0.0.1:6060/debug/pprof/$profile" || result=$?
    done
  fi
  if [[ $result -eq 0 ]]; then
    run_benchmark_client "$variant" udp-pps "${profile_seconds}s" 0s \
      "$profile_dir/udp-connected-profile-load.json" || result=$?
  fi
  if [[ $result -eq 0 ]]; then
    for profile in allocs heap; do
      ip netns exec "$profile_namespace" curl --fail --silent --show-error \
        --output "$profile_dir/udp-connected-$profile-after.pprof" \
        "http://127.0.0.1:6060/debug/pprof/$profile" || result=$?
    done
  fi
  stop_sing_box
  stop_server
  reset_router_rules
  if [[ $result -eq 0 ]]; then
    go tool pprof -top -nodecount=50 "$debug_sing_box" \
      "$profile_dir/udp-connected-cpu.pprof" \
      > "$profile_dir/udp-connected-cpu.txt"
    go tool pprof -top -nodecount=50 -sample_index=alloc_space \
      -base "$profile_dir/udp-connected-allocs-before.pprof" \
      "$debug_sing_box" "$profile_dir/udp-connected-allocs-after.pprof" \
      > "$profile_dir/udp-connected-allocs.txt"
    go tool pprof -top -nodecount=50 -sample_index=inuse_space \
      "$debug_sing_box" "$profile_dir/udp-connected-heap-after.pprof" \
      > "$profile_dir/udp-connected-heap.txt"
  else
    printf '%s\t%s\t%s\n' "$variant" "$repetition" "$result" \
      >> "$output/failures.tsv"
    failed=1
  fi
}

run_variant() {
  local variant=$1
  local repetition=$2
  local result=0
  local variant_index
  case "$variant" in
    direct) variant_index=1 ;;
    ebpf-local) variant_index=2 ;;
    ebpf-shared) variant_index=3 ;;
    redirect) variant_index=4 ;;
    tproxy) variant_index=5 ;;
    tun-mixed) variant_index=6 ;;
    tun-mixed-auto-redirect) variant_index=7 ;;
  esac
  server_port=$((20000 + repetition * 10 + variant_index))
  reset_router_rules
  start_server "$variant" "$repetition" || result=$?
  if [[ $result -eq 0 && $variant != direct ]]; then
    start_sing_box "$variant" "$repetition" || result=$?
  fi
  if [[ $result -eq 0 ]]; then
    run_client "$variant" "$repetition" || result=$?
  fi
  if [[ $variant != direct ]]; then
    record_process_metrics "$variant" "$repetition" || true
  fi
  if [[ $result -eq 0 && $variant == tun-* ]]; then
    record_tun_activity "$variant" "$repetition" || result=$?
  fi
  stop_sing_box
  stop_server
  reset_router_rules
  if [[ $result -ne 0 ]]; then
    printf '%s\t%s\t%s\n' "$variant" "$repetition" "$result" \
      >> "$output/failures.tsv"
    failed=1
  fi
}

record_environment
prepare_policy_rule_set
create_topology

for repetition in $(seq 1 "$repetitions"); do
  while read -r variant; do
    echo "running $variant repetition $repetition" >&2
    run_variant "$variant" "$repetition"
  done < <(printf '%s\n' "${benchmark_variants[@]}" | shuf)
done

for variant in ebpf-local; do
  if [[ -n ${seen_variants[$variant]:-} ]]; then
    echo "validating $variant interception against direct leakage" >&2
    run_local_leak_check "$variant"
  fi
done

for variant in ebpf-shared redirect tproxy; do
  if [[ -n ${seen_variants[$variant]:-} ]]; then
    echo "validating $variant interception against direct leakage" >&2
    run_forwarded_leak_check "$variant"
  fi
done

if ((profile_seconds > 0)); then
  for mode in local shared; do
    if [[ -n ${seen_variants[ebpf-$mode]:-} ]]; then
      echo "profiling eBPF $mode connected UDP for ${profile_seconds}s" >&2
      run_ebpf_udp_profile "$mode"
    fi
  done
fi

exit "$failed"
