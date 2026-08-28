#!/system/bin/sh

set -eu

ROOT=${BENCHMARK_ROOT:-/data/local/tmp/sing-box-inbound-benchmark}
DURATION=${BENCHMARK_DURATION:-5s}
WARMUP=${BENCHMARK_WARMUP:-3s}
CONCURRENCY=${BENCHMARK_CONCURRENCY:-8}
REPETITIONS=${BENCHMARK_REPETITIONS:-5}
TCP_PAYLOAD_SIZE=${BENCHMARK_TCP_PAYLOAD_SIZE:-32768}
UDP_PAYLOAD_SIZE=${BENCHMARK_UDP_PAYLOAD_SIZE:-1200}
SERVER_PORT=5201
APP_ADDRESS=10.89.0.2
ROUTER_APP_ADDRESS=10.89.0.1
ROUTER_SERVER_ADDRESS=10.89.1.1
SERVER_ADDRESS=10.89.1.2

usage() {
  echo "usage: $0 setup|suite|run VARIANT REPETITION|validate VARIANT|cleanup" >&2
  exit 2
}

pid_value() {
  cat "$ROOT/$1.pid"
}

write_configs() {
  cat > "$ROOT/config/redirect.json" <<'EOF'
{"log":{"level":"error","timestamp":true},"inbounds":[{"type":"redirect","tag":"benchmark-in","listen":"0.0.0.0","listen_port":15001}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default_interface":"sbr1","final":"direct"}}
EOF
  cat > "$ROOT/config/tproxy.json" <<'EOF'
{"log":{"level":"error","timestamp":true},"inbounds":[{"type":"tproxy","tag":"benchmark-in","listen":"0.0.0.0","listen_port":15002,"network":["tcp","udp"]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default_interface":"sbr1","final":"direct"}}
EOF
  cat > "$ROOT/config/ebpf-local.json" <<'EOF'
{"log":{"level":"error","timestamp":true},"inbounds":[{"type":"ebpf","tag":"benchmark-in","mode":"local","network":["tcp","udp"],"local":{"dns_mode":"off","cgroup_path":"/sys/fs/cgroup/sing-box-inbound-benchmark","include_uid":[2000],"ipv6":false,"bypass_private_address":false}}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default_interface":"sba0","final":"direct"}}
EOF
  cat > "$ROOT/config/ebpf-shared.json" <<'EOF'
{"log":{"level":"error","timestamp":true},"inbounds":[{"type":"ebpf","tag":"benchmark-in","mode":"shared","network":["tcp","udp"],"shared":{"dns_mode":"off","interface":["sbr0"],"ipv6":false,"bypass_private_address":false}}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default_interface":"sbr1","final":"direct"}}
EOF
  cat > "$ROOT/config/tun-mixed.json" <<'EOF'
{"log":{"level":"error","timestamp":true},"inbounds":[{"type":"tun","tag":"benchmark-in","interface_name":"sb-benchmark","address":["172.19.0.1/30"],"mtu":1500,"stack":"mixed","auto_route":true,"auto_redirect":false,"include_uid":[2000],"route_address":["10.89.1.2/32"]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default_interface":"sba0","final":"direct"}}
EOF
  cat > "$ROOT/config/tun-mixed-auto-redirect.json" <<'EOF'
{"log":{"level":"error","timestamp":true},"inbounds":[{"type":"tun","tag":"benchmark-in","interface_name":"sb-benchmark","address":["172.19.0.1/30"],"mtu":1500,"stack":"mixed","auto_route":true,"auto_redirect":true,"include_uid":[2000],"route_address":["10.89.1.2/32"]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default_interface":"sba0","final":"direct"}}
EOF
}

setup_namespace() {
  namespace=$1
  unshare -n sh -c 'sleep 86400' > /dev/null 2>&1 &
  echo $! > "$ROOT/$namespace.pid"
}

app_net() {
  ip link set lo up
  ip address add "$APP_ADDRESS/24" dev sba0
  ip link set sba0 up
  ip route add default via "$ROUTER_APP_ADDRESS"
}

router_net() {
  ip link set lo up
  ip address add "$ROUTER_APP_ADDRESS/24" dev sbr0
  ip address add "$ROUTER_SERVER_ADDRESS/24" dev sbr1
  ip link set sbr0 up
  ip link set sbr1 up
  echo 1 > /proc/sys/net/ipv4/ip_forward
  iptables -P FORWARD ACCEPT
}

server_net() {
  ip link set lo up
  ip address add "$SERVER_ADDRESS/24" dev sbs0
  ip link set sbs0 up
  ip route add "$APP_ADDRESS/32" via "$ROUTER_SERVER_ADDRESS"
}

server_run() {
  exec "$ROOT/interception-bench" -mode server -listen "$SERVER_ADDRESS:$SERVER_PORT"
}

record_environment() {
  {
    echo "date=$(date -Iseconds 2>/dev/null || date)"
    echo "duration=$DURATION"
    echo "warmup=$WARMUP"
    echo "repetitions=$REPETITIONS"
    echo "concurrency=$CONCURRENCY"
    echo "tcp_payload_size=$TCP_PAYLOAD_SIZE"
    echo "udp_payload_size=$UDP_PAYLOAD_SIZE"
    echo "variants=direct,ebpf-local,ebpf-shared,redirect,tproxy,tun-mixed,tun-mixed-auto-redirect"
    echo "scenarios=tcp-short,tcp-upload,tcp-download,udp-pps,udp-unconnected-pps,udp-churn"
    echo "topology=android-three-network-namespaces"
    echo "sing_box=$($ROOT/sing-box version 2>&1 | head -n 1)"
    uname -a
  } > "$ROOT/environment/run.txt"
}

setup() {
  [ "$(id -u)" = 0 ] || { echo "root is required" >&2; exit 1; }
  [ -x "$ROOT/sing-box" ] || { echo "missing $ROOT/sing-box" >&2; exit 1; }
  [ -x "$ROOT/interception-bench" ] || { echo "missing $ROOT/interception-bench" >&2; exit 1; }
  mkdir -p "$ROOT/config" "$ROOT/environment" "$ROOT/logs" "$ROOT/raw" "$ROOT/validation"
  for variant in direct ebpf-local ebpf-shared redirect tproxy tun-mixed tun-mixed-auto-redirect; do
    mkdir -p "$ROOT/raw/$variant"
  done
  write_configs
  setup_namespace app
  setup_namespace router
  setup_namespace server
  sleep 1
  app=$(pid_value app)
  router=$(pid_value router)
  server=$(pid_value server)
  ip link add sba0 type veth peer name sbr0
  ip link set sba0 netns "$app"
  ip link set sbr0 netns "$router"
  ip link add sbr1 type veth peer name sbs0
  ip link set sbr1 netns "$router"
  ip link set sbs0 netns "$server"
  nsenter -t "$app" -n sh "$0" internal-app-net
  nsenter -t "$router" -n sh "$0" internal-router-net
  nsenter -t "$server" -n sh "$0" internal-server-net
  mkdir /sys/fs/cgroup/sing-box-inbound-benchmark
  nsenter -t "$server" -n sh "$0" internal-server-run > "$ROOT/logs/server.log" 2>&1 &
  echo $! > "$ROOT/server-benchmark.pid"
  record_environment
  getprop > "$ROOT/environment/getprop.txt"
  echo "benchmark topology ready at $ROOT"
}

router_rules() {
  action=$1
  iptables -t nat -F
  iptables -t mangle -F
  iptables -F FORWARD
  iptables -P FORWARD ACCEPT
  ip rule del fwmark 1 table 100 2>/dev/null || true
  ip route flush table 100 2>/dev/null || true
  case "$action" in
    redirect)
      iptables -t nat -A PREROUTING -s "$APP_ADDRESS" -d "$SERVER_ADDRESS" \
        -p tcp --dport "$SERVER_PORT" -j REDIRECT --to-ports 15001
      ;;
    tproxy)
      ip rule add fwmark 1 table 100
      ip route add local 0.0.0.0/0 dev lo table 100
      iptables -t mangle -A PREROUTING -s "$APP_ADDRESS" -d "$SERVER_ADDRESS" \
        -p tcp --dport "$SERVER_PORT" -j TPROXY --on-ip 0.0.0.0 \
        --on-port 15002 --tproxy-mark 0x1/0x1
      iptables -t mangle -A PREROUTING -s "$APP_ADDRESS" -d "$SERVER_ADDRESS" \
        -p udp --dport "$SERVER_PORT" -j TPROXY --on-ip 0.0.0.0 \
        --on-port 15002 --tproxy-mark 0x1/0x1
      ;;
  esac
}

app_block() {
  action=$1
  for network in tcp udp; do
    if [ "$action" = add ]; then
      iptables -A OUTPUT -m owner --uid-owner 2000 -d "$SERVER_ADDRESS" \
        -p "$network" --dport "$SERVER_PORT" -j REJECT
    else
      iptables -D OUTPUT -m owner --uid-owner 2000 -d "$SERVER_ADDRESS" \
        -p "$network" --dport "$SERVER_PORT" -j REJECT 2>/dev/null || true
    fi
  done
}

router_block() {
  action=$1
  for network in tcp udp; do
    if [ "$action" = add ]; then
      iptables -A FORWARD -s "$APP_ADDRESS" -d "$SERVER_ADDRESS" \
        -p "$network" --dport "$SERVER_PORT" -j REJECT
    else
      iptables -D FORWARD -s "$APP_ADDRESS" -d "$SERVER_ADDRESS" \
        -p "$network" --dport "$SERVER_PORT" -j REJECT 2>/dev/null || true
    fi
  done
}

start_box() {
  variant=$1
  repetition=$2
  exec "$ROOT/sing-box" run -c "$ROOT/config/$variant.json" \
    > "$ROOT/logs/$variant-$repetition.log" 2>&1
}

client_run() {
  variant=$1
  if [ "$variant" = ebpf-local ]; then
    # Android su first applies its UID task profile. Move the stopped child
    # back into the benchmark cgroup afterwards, then let it exec the client.
    pid_file="$ROOT/client.pid"
    rm -f "$pid_file"
    su 2000 -c "echo \$\$ > $pid_file; kill -STOP \$\$; exec $ROOT/interception-bench -mode client -target $SERVER_ADDRESS:$SERVER_PORT -scenario all -duration $DURATION -warmup $WARMUP -concurrency $CONCURRENCY -tcp-payload-size $TCP_PAYLOAD_SIZE -udp-payload-size $UDP_PAYLOAD_SIZE" &
    child=$!
    count=0
    while [ ! -s "$pid_file" ] && [ "$count" -lt 100 ]; do
      sleep 0.01
      count=$((count + 1))
    done
    [ -s "$pid_file" ] || { kill "$child" 2>/dev/null || true; return 1; }
    client_pid=$(cat "$pid_file")
    echo "$client_pid" > /sys/fs/cgroup/sing-box-inbound-benchmark/cgroup.procs
    kill -CONT "$client_pid"
    wait "$child"
    return
  fi
  scenarios=all
  [ "$variant" = redirect ] && scenarios=tcp-short,tcp-upload,tcp-download
  exec su 2000 -c "$ROOT/interception-bench -mode client -target $SERVER_ADDRESS:$SERVER_PORT -scenario $scenarios -duration $DURATION -warmup $WARMUP -concurrency $CONCURRENCY -tcp-payload-size $TCP_PAYLOAD_SIZE -udp-payload-size $UDP_PAYLOAD_SIZE"
}

stop_box() {
  if [ -f "$ROOT/box.pid" ]; then
    pid=$(cat "$ROOT/box.pid")
    kill "$pid" 2>/dev/null || true
    sleep 1
    kill -9 "$pid" 2>/dev/null || true
    rm -f "$ROOT/box.pid"
  fi
}

valid_report() {
  report=$1
  [ -s "$report" ] || return 1
  ! grep -Eq '"errors":[[:space:]]*[1-9]|"rate":[[:space:]]*0([.,}]|$)' "$report"
}

validate_variant() {
  variant=$1
  app=$(pid_value app)
  router=$(pid_value router)
  report="$ROOT/validation/$variant-no-direct-leak.json"
  stop_box
  nsenter -t "$router" -n sh "$0" internal-router-rules "$variant"
  case "$variant" in
    ebpf-local)
      nsenter -t "$app" -n sh "$0" internal-start-box "$variant" validation &
      echo $! > "$ROOT/box.pid"
      ;;
    ebpf-shared|redirect|tproxy)
      nsenter -t "$router" -n sh "$0" internal-start-box "$variant" validation &
      echo $! > "$ROOT/box.pid"
      ;;
    *) return 2 ;;
  esac
  sleep 3
  if ! kill -0 "$(cat "$ROOT/box.pid")" 2>/dev/null; then
    stop_box
    return 1
  fi
  if [ "$variant" = ebpf-local ]; then
    nsenter -t "$app" -n sh "$0" internal-app-block add
  else
    nsenter -t "$router" -n sh "$0" internal-router-block add
  fi
  if BENCHMARK_DURATION=1s BENCHMARK_WARMUP=0s BENCHMARK_CONCURRENCY=2 \
    nsenter -t "$app" -n sh "$0" internal-client-run "$variant" > "$report" 2>&1; then
    result=0
  else
    result=$?
  fi
  if [ "$variant" = ebpf-local ]; then
    nsenter -t "$app" -n sh "$0" internal-app-block del
  else
    nsenter -t "$router" -n sh "$0" internal-router-block del
  fi
  stop_box
  nsenter -t "$router" -n sh "$0" internal-router-rules reset
  [ "$result" = 0 ] && valid_report "$report"
}

run_variant() {
  variant=$1
  repetition=$2
  record_environment
  app=$(pid_value app)
  router=$(pid_value router)
  stop_box
  nsenter -t "$router" -n sh "$0" internal-router-rules "$variant"
  case "$variant" in
    direct) ;;
    ebpf-shared|redirect|tproxy)
      nsenter -t "$router" -n sh "$0" internal-start-box "$variant" "$repetition" &
      echo $! > "$ROOT/box.pid"
      ;;
    ebpf-local|tun-mixed|tun-mixed-auto-redirect)
      nsenter -t "$app" -n sh "$0" internal-start-box "$variant" "$repetition" &
      echo $! > "$ROOT/box.pid"
      ;;
    *) echo "unknown variant: $variant" >&2; exit 2 ;;
  esac
  if [ "$variant" != direct ]; then
    sleep 3
    if ! kill -0 "$(cat "$ROOT/box.pid")" 2>/dev/null; then
      cat "$ROOT/logs/$variant-$repetition.log" >&2
      return 1
    fi
  fi
  nsenter -t "$app" -n sh "$0" internal-client-run "$variant" \
    > "$ROOT/raw/$variant/$repetition.json" \
    2> "$ROOT/raw/$variant/$repetition.stderr"
  if [ "$variant" != direct ]; then
    pid=$(cat "$ROOT/box.pid")
    if [ -r "/proc/$pid/status" ]; then
      grep -E '^(VmPeak|VmHWM|VmRSS|Threads|voluntary_ctxt_switches|nonvoluntary_ctxt_switches):' \
        "/proc/$pid/status" > "$ROOT/raw/$variant/$repetition-process.txt" || true
    fi
  fi
  stop_box
  nsenter -t "$router" -n sh "$0" internal-router-rules reset
}

suite() {
  record_environment
  : > "$ROOT/progress.log"
  : > "$ROOT/failures.tsv"
  repetition=1
  while [ "$repetition" -le "$REPETITIONS" ]; do
    case "$repetition" in
      1) order='direct ebpf-local ebpf-shared redirect tproxy tun-mixed tun-mixed-auto-redirect' ;;
      2) order='tproxy tun-mixed direct ebpf-shared tun-mixed-auto-redirect ebpf-local redirect' ;;
      3) order='tun-mixed-auto-redirect redirect ebpf-local direct tun-mixed ebpf-shared tproxy' ;;
      4) order='ebpf-shared ebpf-local tproxy tun-mixed-auto-redirect redirect direct tun-mixed' ;;
      *) order='tun-mixed direct tproxy ebpf-local redirect ebpf-shared tun-mixed-auto-redirect' ;;
    esac
    for variant in $order; do
      echo "$(date +%s) start $variant $repetition" >> "$ROOT/progress.log"
      if "$0" run "$variant" "$repetition"; then
        echo "$(date +%s) done $variant $repetition" >> "$ROOT/progress.log"
      else
        code=$?
        printf '%s\t%s\t%s\n' "$variant" "$repetition" "$code" >> "$ROOT/failures.tsv"
        echo "$(date +%s) fail $variant $repetition code=$code" >> "$ROOT/progress.log"
      fi
    done
    repetition=$((repetition + 1))
  done
  for variant in ebpf-local ebpf-shared redirect tproxy; do
    echo "$(date +%s) validate $variant" >> "$ROOT/progress.log"
    if validate_variant "$variant"; then
      echo "$(date +%s) validated $variant" >> "$ROOT/progress.log"
    else
      code=$?
      printf '%s\t%s\t%s\n' "$variant-leak-check" validation "$code" >> "$ROOT/failures.tsv"
      echo "$(date +%s) validation-failed $variant code=$code" >> "$ROOT/progress.log"
    fi
  done
  echo "$(date +%s) complete" >> "$ROOT/progress.log"
}

cleanup() {
  stop_box
  for name in server-benchmark app router server; do
    if [ -f "$ROOT/$name.pid" ]; then
      kill "$(cat "$ROOT/$name.pid")" 2>/dev/null || true
    fi
  done
  rmdir /sys/fs/cgroup/sing-box-inbound-benchmark 2>/dev/null || true
  echo "benchmark topology removed; results remain in $ROOT"
}

command=${1:-}
case "$command" in
  setup) setup ;;
  suite) suite ;;
  run) [ $# = 3 ] || usage; run_variant "$2" "$3" ;;
  validate) [ $# = 2 ] || usage; validate_variant "$2" ;;
  cleanup) cleanup ;;
  internal-app-net) app_net ;;
  internal-router-net) router_net ;;
  internal-server-net) server_net ;;
  internal-server-run) server_run ;;
  internal-router-rules) router_rules "$2" ;;
  internal-app-block) app_block "$2" ;;
  internal-router-block) router_block "$2" ;;
  internal-start-box) start_box "$2" "$3" ;;
  internal-client-run) client_run "$2" ;;
  *) usage ;;
esac
