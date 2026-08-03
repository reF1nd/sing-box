#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: run-inbound-benchmark.sh --sing-box PATH --benchmark PATH --output DIR [options]

Options:
  --duration DURATION       Measurement duration per scenario (default: 5s)
  --warmup DURATION         Warm-up duration per scenario (default: 1s)
  --repetitions COUNT       Repetitions per inbound (default: 3)
  --concurrency COUNT       Parallel connections or UDP flows (default: 16)
  --variants LIST           Comma-separated inbound variants (default: all)
  --scenarios LIST          Benchmark scenarios passed to the client (default: all)
  --tun-auto-redirect BOOL  Enable TUN auto_redirect (default: true)
  --tun-stack STACK         TUN stack: system, gvisor, or mixed (default: system)
  --profile-sing-box PATH   Profiling-enabled sing-box binary (optional)
  --profile-seconds COUNT   Connected UDP profile duration in seconds (default: 0)
EOF
}

sing_box=
benchmark=
output=
duration=5s
warmup=1s
repetitions=3
concurrency=16
variants=direct,ebpf,redirect,tproxy,tun
scenarios=all
tun_auto_redirect=true
tun_stack=system
profile_sing_box=
profile_seconds=0

while (($# > 0)); do
  case "$1" in
    --sing-box)
      sing_box=$2
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
    --variants)
      variants=$2
      shift 2
      ;;
    --scenarios)
      scenarios=$2
      shift 2
      ;;
    --tun-auto-redirect)
      tun_auto_redirect=$2
      shift 2
      ;;
    --tun-stack)
      tun_stack=$2
      shift 2
      ;;
    --profile-sing-box)
      profile_sing_box=$2
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
    direct|ebpf|redirect|tproxy|tun) ;;
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
if ((profile_seconds > 0)) && [[ -z $profile_sing_box ]]; then
  echo "profile-sing-box is required when profile-seconds is greater than 0" >&2
  exit 2
fi
if [[ $tun_auto_redirect != true && $tun_auto_redirect != false ]]; then
  echo "tun-auto-redirect must be true or false" >&2
  exit 2
fi
case "$tun_stack" in
  system|gvisor|mixed) ;;
  *)
    echo "tun-stack must be system, gvisor, or mixed" >&2
    exit 2
    ;;
esac

for command in ip iptables jq mountpoint ping realpath setpriv shuf ss sysctl; do
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
fi

sing_box=$(realpath "$sing_box")
benchmark=$(realpath "$benchmark")
if [[ -n $profile_sing_box ]]; then
  profile_sing_box=$(realpath "$profile_sing_box")
  if [[ ! -x $profile_sing_box ]]; then
    echo "profile sing-box path must be executable" >&2
    exit 1
  fi
fi
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
app_address=10.89.0.2
router_app_address=10.89.0.1
router_server_address=10.89.1.1
server_address=10.89.1.2
server_port=
redirect_port=15001
tproxy_port=15002
sing_box_pid=
server_pid=
profile_pid=
failed=0

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
    echo "commit=$(git rev-parse HEAD 2>/dev/null || true)"
    echo "date=$(date --iso-8601=seconds)"
    echo "duration=$duration"
    echo "warmup=$warmup"
    echo "repetitions=$repetitions"
    echo "concurrency=$concurrency"
    echo "variants=$variants"
    echo "scenarios=$scenarios"
    echo "tun_auto_redirect=$tun_auto_redirect"
    echo "tun_stack=$tun_stack"
    echo "profile_seconds=$profile_seconds"
    echo "sing_box=$($sing_box version 2>&1 | head -n 1)"
  } > "$output/environment/run.txt"
  uname -a > "$output/environment/uname.txt"
  lscpu > "$output/environment/lscpu.txt" 2>&1 || true
  mount | grep cgroup > "$output/environment/cgroup-mounts.txt" || true
  sysctl kernel.unprivileged_bpf_disabled > "$output/environment/bpf.txt" 2>&1 || true
  ip -details link show > "$output/environment/links.txt"
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
  ip -n "$app_namespace" address add "$app_address/24" dev "$app_interface"
  ip -n "$app_namespace" link set "$app_interface" up
  ip -n "$app_namespace" route add default via "$router_app_address"

  ip -n "$router_namespace" link set lo up
  ip -n "$router_namespace" address add "$router_app_address/24" dev "$router_app_interface"
  ip -n "$router_namespace" address add "$router_server_address/24" dev "$router_server_interface"
  ip -n "$router_namespace" link set "$router_app_interface" up
  ip -n "$router_namespace" link set "$router_server_interface" up
  ip -n "$router_namespace" route add default via "$server_address"
  ip netns exec "$router_namespace" sysctl -q -w net.ipv4.ip_forward=1
  ip netns exec "$router_namespace" iptables -P FORWARD ACCEPT

  ip -n "$server_namespace" link set lo up
  ip -n "$server_namespace" address add "$server_address/24" dev "$server_interface"
  ip -n "$server_namespace" link set "$server_interface" up
  ip -n "$server_namespace" route add "$app_address/32" via "$router_server_address"

  mkdir "$cgroup_path"
  ip netns exec "$app_namespace" ping -c 1 -W 2 "$server_address" >/dev/null

  {
    for namespace in "$app_namespace" "$router_namespace" "$server_namespace"; do
      echo "### $namespace"
      ip -n "$namespace" -details address show
      ip -n "$namespace" route show table all
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
  jq -n --argjson inbound "$inbound" --arg debug_listen "$debug_listen" '{
    log: {level: "error", timestamp: true},
    inbounds: [$inbound],
    outbounds: [{type: "direct", tag: "direct"}],
    route: {final: "direct"}
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
  local executable=$sing_box
  local debug_listen=
  local inbound

  case "$variant" in
    ebpf|ebpf-profile|ebpf-leak-check)
      namespace=$app_namespace
      if [[ $variant == ebpf-profile ]]; then
        executable=$profile_sing_box
        debug_listen=127.0.0.1:6060
      fi
      inbound=$(jq -n --arg cgroup "$cgroup_path" '{
        type: "ebpf",
        tag: "benchmark-in",
        cgroup_path: $cgroup,
        network: ["tcp", "udp"],
        dns_mode: "off"
      }')
      ;;
    redirect)
      inbound=$(jq -n --argjson port "$redirect_port" '{
        type: "redirect",
        tag: "benchmark-in",
        listen: "0.0.0.0",
        listen_port: $port
      }')
      ip netns exec "$router_namespace" iptables -t nat -A PREROUTING \
        -s "$app_address" -d "$server_address" -p tcp --dport "$server_port" \
        -j REDIRECT --to-ports "$redirect_port"
      ;;
    tproxy)
      inbound=$(jq -n --argjson port "$tproxy_port" '{
        type: "tproxy",
        tag: "benchmark-in",
        listen: "0.0.0.0",
        listen_port: $port,
        network: ["tcp", "udp"]
      }')
      ip netns exec "$router_namespace" ip rule add fwmark 1 table 100
      ip netns exec "$router_namespace" ip route add local 0.0.0.0/0 dev lo table 100
      for network in tcp udp; do
        ip netns exec "$router_namespace" iptables -t mangle -A PREROUTING \
          -s "$app_address" -d "$server_address" -p "$network" --dport "$server_port" \
          -j TPROXY --on-ip 0.0.0.0 --on-port "$tproxy_port" --tproxy-mark 0x1/0x1
      done
      ;;
    tun)
      inbound=$(jq -n \
        --arg server "$server_address/32" \
        --arg stack "$tun_stack" \
        --argjson autoRedirect "$tun_auto_redirect" \
        '{
        type: "tun",
        tag: "benchmark-in",
        interface_name: "sb-benchmark",
        address: "172.19.0.1/30",
        mtu: 1500,
        auto_route: true,
        auto_redirect: $autoRedirect,
        stack: $stack,
        route_address: [$server]
      } + if $autoRedirect then {} else {exclude_uid: [0]} end')
      ;;
    *)
      echo "unknown variant: $variant" >&2
      return 1
      ;;
  esac

  write_common_config "$inbound" "$config" "$debug_listen"
  if [[ $variant == ebpf || $variant == ebpf-profile || $variant == ebpf-leak-check ]]; then
    ip netns exec "$namespace" bash -c '
      if ! mountpoint -q /sys/fs/cgroup; then
        mount -t cgroup2 none /sys/fs/cgroup
      fi
      exec "$@"
    ' benchmark-ebpf "$executable" run -c "$config" > "$log" 2>&1 &
  else
    ip netns exec "$namespace" "$executable" run -c "$config" > "$log" 2>&1 &
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
  ip netns exec "$router_namespace" iptables -t nat -F
  ip netns exec "$router_namespace" iptables -t mangle -F
  ip netns exec "$app_namespace" iptables -t filter -F OUTPUT
  ip netns exec "$router_namespace" ip rule del fwmark 1 table 100 2>/dev/null || true
  ip netns exec "$router_namespace" ip route flush table 100 2>/dev/null || true
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
      udp-pps|udp-unconnected-pps) ;;
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
  local client_uid=${6:-}
  mkdir -p "$(dirname "$raw")"

  local command=(
    "$benchmark"
    -mode client
    -target "$server_address:$server_port"
    -scenario "$scenarios"
    -duration "$client_duration"
    -warmup "$client_warmup"
    -concurrency "$concurrency"
    -payload-size 1200
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
  if [[ $variant == ebpf || $variant == ebpf-profile || $variant == ebpf-leak-check ]]; then
    bash -c 'echo $$ > "$1/cgroup.procs"; shift; exec ip netns exec "$@"' \
      benchmark-cgroup "$cgroup_path" "$app_namespace" "${namespace_command[@]}" > "$raw"
  else
    ip netns exec "$app_namespace" "${namespace_command[@]}" > "$raw"
  fi
  jq -e '.results | length > 0 and all(.errors == 0)' "$raw" >/dev/null
}

run_ebpf_leak_check() {
  local variant=ebpf-leak-check
  local repetition=1
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
      ip netns exec "$app_namespace" iptables -t filter -A OUTPUT \
        -m owner --uid-owner "$client_uid" \
        -d "$server_address" -p "$network" --dport "$server_port" \
        -j REJECT || result=$?
    done
  fi
  if [[ $result -eq 0 ]]; then
    run_benchmark_client "$variant" tcp-short,udp-pps,udp-unconnected-pps \
      1s 0s "$output/validation/ebpf-no-direct-leak.json" "$client_uid" || result=$?
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

run_ebpf_udp_profile() {
  local variant=ebpf-profile
  local repetition=1
  local result=0
  server_port=20992
  reset_router_rules
  start_server "$variant" "$repetition" || result=$?
  if [[ $result -eq 0 ]]; then
    start_sing_box "$variant" "$repetition" || result=$?
  fi
  if [[ $result -eq 0 ]]; then
    for _ in $(seq 1 30); do
      if ip netns exec "$app_namespace" curl --fail --silent --output /dev/null \
        http://127.0.0.1:6060/debug/pprof/; then
        break
      fi
      sleep 0.1
    done
    run_benchmark_client "$variant" udp-pps 1s 0s \
      "$output/profiles/udp-connected-warmup.json" || result=$?
  fi
  if [[ $result -eq 0 ]]; then
    ip netns exec "$app_namespace" curl --fail --silent --show-error \
      --output "$output/profiles/udp-connected-cpu.pprof" \
      "http://127.0.0.1:6060/debug/pprof/profile?seconds=$profile_seconds" &
    profile_pid=$!
    sleep 0.2
    run_benchmark_client "$variant" udp-pps "${profile_seconds}s" 0s \
      "$output/profiles/udp-connected-cpu-load.json" || result=$?
    wait "$profile_pid" || result=$?
    profile_pid=
  fi
  if [[ $result -eq 0 ]]; then
    for profile in allocs mutex block; do
      ip netns exec "$app_namespace" curl --fail --silent --show-error \
        --output "$output/profiles/udp-connected-$profile-before.pprof" \
        "http://127.0.0.1:6060/debug/pprof/$profile" || result=$?
    done
  fi
  if [[ $result -eq 0 ]]; then
    run_benchmark_client "$variant" udp-pps "${profile_seconds}s" 0s \
      "$output/profiles/udp-connected-profile-load.json" || result=$?
  fi
  if [[ $result -eq 0 ]]; then
    for profile in allocs mutex block; do
      ip netns exec "$app_namespace" curl --fail --silent --show-error \
        --output "$output/profiles/udp-connected-$profile-after.pprof" \
        "http://127.0.0.1:6060/debug/pprof/$profile" || result=$?
    done
  fi
  stop_sing_box
  stop_server
  reset_router_rules
  if [[ $result -eq 0 ]]; then
    go tool pprof -top -nodecount=50 "$profile_sing_box" \
      "$output/profiles/udp-connected-cpu.pprof" \
      > "$output/profiles/udp-connected-cpu.txt"
    go tool pprof -top -nodecount=50 -sample_index=alloc_space \
      -base "$output/profiles/udp-connected-allocs-before.pprof" \
      "$profile_sing_box" "$output/profiles/udp-connected-allocs-after.pprof" \
      > "$output/profiles/udp-connected-allocs.txt"
    go tool pprof -top -nodecount=50 \
      -base "$output/profiles/udp-connected-mutex-before.pprof" \
      "$profile_sing_box" "$output/profiles/udp-connected-mutex-after.pprof" \
      > "$output/profiles/udp-connected-mutex.txt"
    go tool pprof -top -nodecount=50 \
      -base "$output/profiles/udp-connected-block-before.pprof" \
      "$profile_sing_box" "$output/profiles/udp-connected-block-after.pprof" \
      > "$output/profiles/udp-connected-block.txt"
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
    ebpf) variant_index=2 ;;
    redirect) variant_index=3 ;;
    tproxy) variant_index=4 ;;
    tun) variant_index=5 ;;
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
create_topology

for repetition in $(seq 1 "$repetitions"); do
  while read -r variant; do
    echo "running $variant repetition $repetition" >&2
    run_variant "$variant" "$repetition"
  done < <(printf '%s\n' "${benchmark_variants[@]}" | shuf)
done

if [[ -n ${seen_variants[ebpf]:-} ]]; then
  echo "validating eBPF TCP and UDP interception against direct leakage" >&2
  run_ebpf_leak_check
fi

if ((profile_seconds > 0)) && [[ -n ${seen_variants[ebpf]:-} ]]; then
  echo "profiling eBPF connected UDP for ${profile_seconds}s" >&2
  run_ebpf_udp_profile
fi

exit "$failed"
