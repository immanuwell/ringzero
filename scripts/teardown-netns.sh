#!/usr/bin/env bash
# Tears down everything setup-netns.sh created.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

for f in /tmp/ringzero-backend1.pid /tmp/ringzero-backend2.pid; do
    if [ -f "$f" ]; then
        kill "$(cat "$f")" 2>/dev/null
        rm -f "$f"
    fi
done

"$here/zig-out/bin/ringzero" detach --iface veth-c --purge 2>/dev/null

ip link del veth-c 2>/dev/null
ip link del veth-b1 2>/dev/null
ip link del veth-b2 2>/dev/null

ip netns del client 2>/dev/null
ip netns del backend1 2>/dev/null
ip netns del backend2 2>/dev/null

echo "teardown complete"
