#!/usr/bin/env bash
# Builds a local demo topology using network namespaces so the whole LB can
# be exercised on a single dev box with no real NIC or second machine:
#
#   [client ns] --veth-- [root ns: XDP attaches here] --veth-- [backend1 ns]
#                                                     \-veth-- [backend2 ns]
#
# The root ns plays the role of the router/LB box in a real deployment: the
# XDP program attaches to veth-c (facing the client) in *native* mode and
# redirects matching traffic out veth-b1/veth-b2 (facing the backends),
# rewriting src/dst MAC and dst IP along the way.
#
# veth does support native-mode XDP (unlike most virtual NICs), but its
# redirect (ndo_xdp_xmit) target needs its own XDP-enabled RX queue to
# redirect into -- so this script also loads a trivial XDP_PASS program
# (bpf/xdp_pass.o) onto each backend-facing peer purely to switch that
# machinery on. Real deployments (redirecting to a physical NIC egress, or
# not redirecting cross-device at all) don't need this.
#
# See the README for the full pps-measurement caveats of this local,
# single-box, all-veth setup versus real multi-queue hardware.
set -euo pipefail

VIP=10.99.0.1
VIP_PORT=9000

CLIENT_IP=10.10.0.2/24
ROUTER_CLIENT_IP=10.10.0.1/24
BACKEND1_IP=10.20.0.2/24
ROUTER_BACKEND1_IP=10.20.0.1/24
BACKEND2_IP=10.30.0.2/24
ROUTER_BACKEND2_IP=10.30.0.1/24

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

echo "== creating namespaces =="
ip netns add client
ip netns add backend1
ip netns add backend2

echo "== creating veth pairs =="
ip link add veth-c type veth peer name veth-c-peer
ip link add veth-b1 type veth peer name veth-b1-peer
ip link add veth-b2 type veth peer name veth-b2-peer

ip link set veth-c-peer netns client
ip link set veth-b1-peer netns backend1
ip link set veth-b2-peer netns backend2

echo "== addressing =="
ip addr add "$ROUTER_CLIENT_IP" dev veth-c
ip addr add "$ROUTER_BACKEND1_IP" dev veth-b1
ip addr add "$ROUTER_BACKEND2_IP" dev veth-b2
ip link set veth-c up
ip link set veth-b1 up
ip link set veth-b2 up

ip netns exec client ip addr add "$CLIENT_IP" dev veth-c-peer
ip netns exec client ip link set veth-c-peer up
ip netns exec client ip link set lo up
# veth defaults to deferring checksum computation to "hardware" offload
# (tx-checksum-ip-generic), which doesn't exist for a virtual device -- the
# byte a real NIC would finish gets left incomplete instead. Force real
# checksums so what XDP reads and rewrites is well-formed.
ip netns exec client ethtool -K veth-c-peer tx off 2>/dev/null || true
ethtool -K veth-c tx off 2>/dev/null || true

ip netns exec backend1 ip addr add "$BACKEND1_IP" dev veth-b1-peer
ip netns exec backend1 ip link set veth-b1-peer up
ip netns exec backend1 ip link set lo up
ip netns exec backend1 ethtool -K veth-b1-peer tx off rx off gro off gso off 2>/dev/null || true
ethtool -K veth-b1 tx off rx off gro off gso off 2>/dev/null || true

ip netns exec backend2 ip addr add "$BACKEND2_IP" dev veth-b2-peer
ip netns exec backend2 ip link set veth-b2-peer up
ip netns exec backend2 ip link set lo up
ip netns exec backend2 ethtool -K veth-b2-peer tx off rx off gro off gso off 2>/dev/null || true
ethtool -K veth-b2 tx off rx off gro off gso off 2>/dev/null || true

echo "== enabling native XDP redirect targets on backend peers =="
ip netns exec backend1 ip link set dev veth-b1-peer xdp obj "$here/bpf/xdp_pass.o" sec xdp
ip netns exec backend2 ip link set dev veth-b2-peer xdp obj "$here/bpf/xdp_pass.o" sec xdp

echo "== faking VIP reachability from the client =="
# There's no real host owning $VIP anywhere -- in production the LB's real
# NIC would answer ARP for it, or it'd be announced via BGP to the upstream
# router. Here we just point the client straight at the router's MAC.
ROUTER_MAC=$(cat /sys/class/net/veth-c/address)
ip netns exec client ip route add "$VIP/32" dev veth-c-peer
ip netns exec client ip neigh replace "$VIP" lladdr "$ROUTER_MAC" dev veth-c-peer nud permanent

# Optional: a UDP packet counter in each backend netns, purely so you can
# watch *something* receiving traffic while poking at the demo by hand. Note
# that end-to-end delivery through nested network namespaces on a given
# kernel/host can be sensitive to local networking config (conntrack, GRO,
# sysctls) in ways that have nothing to do with the LB itself -- if these
# logs stay at 0 while `ringzero stats` is climbing, don't read that as "the
# eBPF program is broken": use `scripts/verify_datapath.py` (see README) to
# check the program's packet rewriting in isolation via BPF_PROG_TEST_RUN,
# which sidesteps the rest of the network stack entirely.
echo "== starting UDP sink listeners on backends (best-effort, see note in script) =="
ip netns exec backend1 python3 -u "$here/scripts/udp_sink.py" "${BACKEND1_IP%/*}" "$VIP_PORT" \
    > /tmp/ringzero-backend1.log 2>&1 &
echo $! > /tmp/ringzero-backend1.pid
ip netns exec backend2 python3 -u "$here/scripts/udp_sink.py" "${BACKEND2_IP%/*}" "$VIP_PORT" \
    > /tmp/ringzero-backend2.log 2>&1 &
echo $! > /tmp/ringzero-backend2.pid

echo "== loading and attaching the XDP program =="
"$here/zig-out/bin/ringzero" attach --iface veth-c --mode native

echo "== configuring VIP and backends =="
"$here/zig-out/bin/ringzero" vip-add --vip "$VIP" --port "$VIP_PORT" --proto udp

B1_MAC=$(ip netns exec backend1 cat /sys/class/net/veth-b1-peer/address)
B1_ROUTER_MAC=$(cat /sys/class/net/veth-b1/address)
"$here/zig-out/bin/ringzero" backend-add --vip "$VIP:$VIP_PORT/udp" \
    --addr "${BACKEND1_IP%/*}" --mac "$B1_MAC" --router-mac "$B1_ROUTER_MAC" --iface veth-b1

B2_MAC=$(ip netns exec backend2 cat /sys/class/net/veth-b2-peer/address)
B2_ROUTER_MAC=$(cat /sys/class/net/veth-b2/address)
"$here/zig-out/bin/ringzero" backend-add --vip "$VIP:$VIP_PORT/udp" \
    --addr "${BACKEND2_IP%/*}" --mac "$B2_MAC" --router-mac "$B2_ROUTER_MAC" --iface veth-b2

echo "== done =="
"$here/zig-out/bin/ringzero" list
echo
echo "try: ip netns exec client $here/bench/floodgen $VIP $VIP_PORT 5"
echo "then: $here/zig-out/bin/ringzero stats --watch"
