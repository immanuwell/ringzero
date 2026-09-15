# ringzero

A small, from-scratch L4 load balancer built to show off what eBPF/XDP make
possible: processing packets **inside the kernel's own receive path** — ring
0, before a socket buffer is even allocated — so that a single box can
forward tens of millions of packets per second on real multi-queue hardware.
Its name is the whole pitch: the packet-forwarding logic in `bpf/xdp_lb.c`
never leaves kernel ring 0 to do its job. It's directly inspired by
[Katran](https://github.com/facebookincubator/katran) (Facebook's production
L4 load balancer) but stripped down to be readable end-to-end in an
afternoon — this is a teaching/demo project, not a production one.

- **Data plane**: `bpf/xdp_lb.c`, a C program compiled to eBPF bytecode and
  attached to a NIC's XDP hook. This is the part that actually forwards
  packets, and it never involves the userspace program below at runtime.
- **Control plane**: `src/*.zig`, a Zig CLI (`ringzero`) that loads the eBPF
  program, manages which VIPs/backends exist, health-checks backends, builds
  the Maglev consistent-hash table, and reports live stats — everything the
  data plane needs, but nothing it can't run without.

## Why this can hit 10M+ pps and a normal proxy can't

A conventional proxy (nginx, HAProxy, a userspace load balancer) sees a
packet only after the kernel has: fired an interrupt, allocated an `sk_buff`,
walked the IP/UDP or IP/TCP stack, matched a socket, and copied data into a
buffer a userspace `read()` can see. Each of those steps costs real CPU
cycles and cache misses, and there's a socket/connection's worth of state to
maintain per flow.

XDP runs a BPF program **inside the NIC driver's poll loop**, on the raw
DMA buffer, before any of that happens:

- no `sk_buff` allocation for packets that get forwarded or dropped,
- no walk through the IP/netfilter/socket stack,
- the same CPU core that received the packet (via RSS/multi-queue) processes
  it, so work scales linearly with cores/queues with no cross-core handoff,
- the verifier proves the program terminates and stays in bounds *before*
  it's allowed to run, so the kernel doesn't need runtime safety checks in
  the hot path,
- decisions are O(1) map lookups (hash maps, array maps) — no per-flow
  connection table to walk, no locks per packet.

This project's `xdp_lb_prog` does exactly four things per packet: parse the
headers, look up the VIP in a hash map, hash the flow into a per-VIP Maglev
table to pick a backend, and rewrite+redirect. All O(1), all inside the
driver's own poll loop. That's the entire reason Katran-style load balancers
can run at line rate on commodity NICs, and it's the whole point of this
repo.

## Architecture

```
                       ┌──────────────────────────────┐
   client ──packet──▶  │  NIC driver RX poll loop      │
                       │    └▶ xdp_lb_prog (eBPF)      │──redirect──▶ backend
                       │         reads: vip_map        │
                       │         reads: maglev_map     │
                       │         reads: backend_map    │
                       │         writes: stats_map     │
                       └──────────────────────────────┘
                                     ▲
                                     │ loads program, manages maps
                                     │
                       ┌──────────────────────────────┐
                       │  ringzero (Zig control plane)   │
                       │   attach / vip-add /          │
                       │   backend-add / healthcheck /  │
                       │   stats                        │
                       └──────────────────────────────┘
```

**Packet path** (`bpf/xdp_lb.c`):
1. Parse Ethernet/IPv4/{TCP,UDP} with explicit verifier-required bounds
   checks (no options support — packets with IP options fall back to
   `XDP_PASS`, i.e. the normal kernel path handles them).
2. Look up `(dst_ip, dst_port, proto)` in `vip_map`. No match → `XDP_PASS`
   (this program is a transparent bump-in-the-wire for anything that isn't
   one of its VIPs).
3. Hash the flow's 5-tuple and index into that VIP's slice of
   `maglev_map` — a precomputed
   [Maglev](https://research.google/pubs/pub44824/) consistent-hashing
   table, so every packet in a flow lands on the same backend, and backend
   churn only reshuffles ~1/N of flows instead of nearly all of them (the
   problem with naive `hash % backend_count`).
4. DNAT the destination IP and MAC to the chosen backend (no port
   translation — this is a DSR-style design, same as Katran), fix up the
   IP/L4 checksums incrementally (not touching the payload), and
   `bpf_redirect()` it out towards the backend, or `XDP_TX` it back out the
   ingress interface if no separate egress interface is configured.
5. Bump per-CPU packet/byte/drop counters.

**Control plane** (`src/*.zig`, binary name `ringzero`) is a normal userspace
program that talks to the kernel via `libbpf`. It's a *control* plane in the
literal sense: once `attach` has loaded the program and pinned its maps
under `/sys/fs/bpf/ringzero`, `ringzero` can exit and the data plane keeps
running with zero userspace involvement. Later invocations of `vip-add`,
`backend-add`, `stats`, etc. just open the pinned maps and read/write them —
there's no daemon required to keep traffic flowing, only for the parts that
inherently need something checking on a schedule (`healthcheck`, `stats
--watch`).

Backend health/liveness and the Maglev table are entirely a control-plane
concern: `backend-add`/`backend-set`/`healthcheck` recompute and push the
full table for a VIP whenever its backend set changes. The data plane just
does array lookups; it has no idea what "healthy" means beyond a bit it
reads out of `backend_map`.

## Repo layout

```
bpf/
  common.h      Struct/constant definitions shared by the BPF C program
                and the Zig control plane (single source of truth, kept
                dependency-free so both toolchains parse it identically).
  xdp_lb.c      The data plane.
  xdp_pass.c    Trivial XDP_PASS program, only used by the local netns demo
                (see below).
src/
  main.zig      ringzero CLI: attach/detach/vip-add/backend-add/backend-set/
                list/stats/healthcheck.
  maglev.zig    The consistent-hashing table builder.
  c.zig         The one @cImport boundary (libbpf + common.h) everything
                else in src/ goes through.
bench/
  floodgen.c    Multithreaded UDP packet generator (sendmmsg-batched) for
                putting load on the demo.
scripts/
  setup-netns.sh / teardown-netns.sh
                Single-box demo topology using network namespaces + veth,
                so you can see this run without a second machine or a real
                NIC.
  verify_datapath.py
                Validates the data plane's packet rewriting in isolation,
                via BPF_PROG_TEST_RUN — see "Verifying correctness" below.
```

## Building

Needs: `clang`/`llvm` (BPF codegen), `bpftool`, `libbpf-dev`, and Zig
(developed against a `0.16.0-dev` snapshot; check `build.zig.zon` for the
exact minimum version it was written against). On Ubuntu:

```
sudo apt install clang llvm libbpf-dev linux-tools-common linux-tools-generic
```

Then:

```
make bpf     # generates bpf/vmlinux.h from the running kernel's BTF, compiles xdp_lb.o + xdp_pass.o
make zig     # builds zig-out/bin/ringzero
make bench   # builds bench/floodgen
# or just: make
```

`bpf/vmlinux.h` is regenerated from your *currently running* kernel's BTF
(`bpftool btf dump file /sys/kernel/btf/vmlinux`) — this is
[CO-RE](https://nakryiko.com/posts/bpf-core-reference-guide/) in spirit
(single struct/type source instead of hand-copied kernel headers), though
this project doesn't currently ship portable CO-RE relocations across kernel
versions; it compiles fresh against whatever kernel you build it on.

## Using `ringzero`

```
ringzero attach --iface IFACE [--obj bpf/xdp_lb.o] [--mode auto|native|generic] [--pindir DIR]
ringzero detach --iface IFACE [--purge] [--pindir DIR]
ringzero vip-add --vip IP --port PORT --proto tcp|udp [--pindir DIR]
ringzero backend-add --vip IP:PORT/proto --addr IP --mac MAC --router-mac MAC --iface IFACE [--pindir DIR]
ringzero backend-set --id ID (--up|--down) [--pindir DIR]
ringzero list [--pindir DIR]
ringzero stats [--watch] [--interval SEC] [--pindir DIR]
ringzero healthcheck [--interval SEC] [--timeout-ms MS] [--pindir DIR]
```

`--mac`/`--router-mac` are static, operator-provided config (the backend's
own MAC, and the MAC of *this box's* interface facing that backend) rather
than resolved automatically via ARP — this mirrors how real DSR load
balancers are configured (backends are usually on a directly-attached
segment with statically-known neighbors) and keeps the control plane simple.
`healthcheck` does a TCP-connect probe for TCP backends; UDP backends have
no protocol-level reachability probe without an application-specific check,
so they're treated as always-healthy until you `backend-set --down` them
manually — a real deployment would plug an app-aware check in here.

## Running the local demo

No physical NIC or second machine needed — `scripts/setup-netns.sh` builds a
topology out of network namespaces and veth pairs (client ↔ router ↔ two
backends), attaches the XDP program, and configures a VIP with both
backends behind it:

```
sudo ./scripts/setup-netns.sh
sudo ip netns exec client ./bench/floodgen 10.99.0.1 9000 5
sudo ./zig-out/bin/ringzero stats --watch
sudo ./scripts/teardown-netns.sh
```

Watch `packets`/`pps` in `ringzero stats` climb while `floodgen` runs — that's
the data plane matching the VIP, consistent-hashing the flow, rewriting, and
redirecting every single packet, entirely in-kernel.

### Verifying correctness

Each backend namespace also runs a small UDP counter
(`scripts/udp_sink.py`, logged to `/tmp/proxy-lb-backend*.log`) so you can
watch packets actually arrive. Whether it shows nonzero counts depends on
your host's networking stack, sysctls, and whatever else is running
alongside these fresh namespaces — cross-namespace UDP delivery over veth
can be sensitive to things (conntrack, GRO/offload state, cgroup networking
setups) that have nothing to do with this project's code.

If you want to check the *data plane itself* — independent of your local
networking config entirely — use `bpftool prog run` (`BPF_PROG_TEST_RUN`) to
feed the loaded program a crafted packet directly and inspect what it
produces, with no NIC, socket, or routing involved:

```
sudo bpftool net show                     # find veth-c's attached prog id
sudo ./scripts/verify_datapath.py --prog-id <id> \
    --vip 10.99.0.1 --vip-port 9000 --proto udp --expect-dst 10.20.0.2
```

This constructs a real Ethernet/IP/UDP packet, runs it through the exact
loaded bytecode, and checks that the output has a valid rewritten
IP/UDP checksum and the expected backend as its new destination. This is
how the checksum-rewriting logic in `xdp_lb.c` was actually validated during
development, and it's a good technique to know in general: `bpftool prog
run` lets you unit-test a BPF program's logic the same way you'd unit-test
any other function, without needing a working end-to-end network path.

### A note on the numbers you'll actually see locally

This demo runs entirely on veth pairs inside one kernel, processed by
whatever single CPU services that interface's single RX queue — there's no
multi-queue RSS spreading work across cores the way a real NIC would. Expect
low-single-digit-million pps at best on a dev box, not 10M — that ceiling is
a property of this specific test rig, not of XDP or this code. The point of
the demo is to see the *mechanism* work (VIP matching, consistent hashing,
rewriting, redirecting, all in-kernel with zero userspace round-trips per
packet), not to benchmark peak throughput on loopback interfaces.

To get anywhere near the number in this repo's name you need what Katran
actually runs on: multi-queue NICs with native XDP driver support (e.g.
Mellanox mlx5, Intel i40e/ice), RSS spreading flows across many cores, and
native (`XDP_FLAGS_DRV_MODE`) attachment — `ringzero attach --mode native`
against a real NIC, no `xdp_pass.c` workaround needed (that workaround is
specifically because redirecting *between two veth peers* needs both ends
XDP-enabled to get a receive-queue data structure to redirect into; a real
NIC's egress doesn't have that requirement).

## What's simplified vs. Katran

This is a learning project, not a Katran reimplementation. Notably missing:

- **No IPIP/GUE encapsulation.** Katran typically encapsulates the original
  packet (DSR via tunneling) so it can route backends anywhere layer-3
  reachable. This project does header rewriting with backends on a directly
  attached segment (real, statically-configured MACs) instead — simpler to
  read, more restrictive to deploy.
- **No BGP/ECMP integration.** Katran's control plane announces VIPs via
  BGP so upstream routers ECMP traffic across a fleet of LB boxes. Here, a
  single box's `attach` is the whole story.
- **IPv4 only**, no IPv6.
- **Health checking is a basic TCP connect probe**, not the pluggable,
  app-aware checks a real fleet needs.
- **No CO-RE portability** across kernel versions (see "Building" above).

## License

No license file yet — add one before you rely on this for anything beyond
poking at eBPF.
