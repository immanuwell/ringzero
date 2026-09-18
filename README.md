# ringzero

A small L4 load balancer built to show what eBPF and XDP can do. It runs inside the kernel's packet receive path, in ring 0, before the kernel even builds a socket buffer for the packet. That's why one box can forward tens of millions of packets per second on the right hardware.

The design is copied from [Katran](https://github.com/facebookincubator/katran), Facebook's production load balancer. This version is much smaller. You can read the whole thing in an afternoon. It's a demo and a learning project, not something you'd run in production.

## Architecture

![ringzero architecture](media/diagram.svg)

There are two parts:

- **Data plane**: `bpf/xdp_lb.c`. A C program compiled to eBPF bytecode and attached to a network interface. This is the part that forwards packets. It never talks to the control plane while running.
- **Control plane**: `src/*.zig`. A Zig CLI called `ringzero`. It loads the eBPF program, manages backends, checks their health, and reports stats.

## How a packet gets forwarded

1. The NIC driver hands the raw frame to `xdp_lb_prog`. No socket buffer exists yet.
2. The program checks if the destination IP, port, and protocol match one of its virtual IPs (`vip_map`). If not, it passes the packet up to the normal kernel network stack, untouched.
3. It hashes the packet's 5-tuple and looks up a backend in a per-VIP Maglev table (`maglev_map`). This is [Maglev](https://research.google/pubs/pub44824/) consistent hashing, the same algorithm Katran uses. Every packet in a flow lands on the same backend. When a backend is added or removed, only a small fraction of flows move to a new backend, not almost all of them.
4. It rewrites the destination IP and MAC to the chosen backend and redirects the packet there. No port translation happens. This is direct server return, the same approach Katran uses.
5. It bumps a per-CPU packet counter.

A handful of map lookups, all O(1). That's the whole reason this can run at line rate: no memory allocation, no walk through the IP stack, no per-flow connection table, no lock contention.

## Why this is fast and a normal proxy isn't

A normal proxy (nginx, HAProxy, a userspace load balancer) sees a packet only after the kernel has fired an interrupt, allocated a socket buffer, walked the IP and TCP/UDP stack, matched a socket, and copied the data somewhere a `read()` call can see it. Each step costs CPU cycles and cache misses.

XDP skips all of that for packets it forwards or drops. The eBPF verifier proves the program is safe before it's allowed to load, so the kernel doesn't need runtime safety checks while it's running. And because RSS spreads incoming packets across multiple NIC queues, each CPU core processes its own share of traffic with no cross-core handoff.

## Repository layout

```
bpf/
  common.h      Struct and constant definitions shared by the BPF program
                and the Zig control plane.
  xdp_lb.c      The data plane.
  xdp_pass.c    A trivial XDP_PASS program, used only by the local demo
                (explained below).
src/
  main.zig      The ringzero CLI: attach, detach, vip-add, vip-del,
                backend-add, backend-set, backend-del, list, stats,
                healthcheck.
  maglev.zig    The consistent-hashing table builder.
  c.zig         The single point where Zig imports libbpf and common.h.
bench/
  floodgen.c    A multithreaded UDP packet generator for load testing.
scripts/
  setup-netns.sh / teardown-netns.sh
                A demo topology built from network namespaces, so you can
                run this without a second machine or a real NIC.
  verify_datapath.py
                Checks the data plane's packet rewriting in isolation. See
                "Checking correctness" below.
```

## Building

You need clang, llvm, bpftool, libbpf-dev, and Zig 0.16.0. On Ubuntu:

```
sudo apt install clang llvm libbpf-dev linux-tools-common linux-tools-generic ethtool
```

Then:

```
make bpf     # generates bpf/vmlinux.h from your kernel's BTF, builds xdp_lb.o and xdp_pass.o
make zig     # builds zig-out/bin/ringzero
make bench   # builds bench/floodgen
# or just: make
```

You need a kernel with BTF (`/sys/kernel/btf/vmlinux`), version 5.6 or newer, which is where batched map updates arrived.

`bpf/vmlinux.h` is generated from whatever kernel you build on, using its BTF data. This project doesn't ship portable CO-RE relocations across kernel versions yet. It compiles fresh each time.

## Using the CLI

```
ringzero attach --iface IFACE [--obj bpf/xdp_lb.o] [--mode auto|native|generic] [--pindir DIR]
ringzero detach --iface IFACE [--purge] [--pindir DIR]
ringzero vip-add --vip IP --port PORT --proto tcp|udp [--pindir DIR]
ringzero backend-add --vip IP:PORT/proto --addr IP --mac MAC --router-mac MAC --iface IFACE [--pindir DIR]
ringzero backend-set --id ID (--up|--down) [--pindir DIR]
ringzero backend-del --id ID [--pindir DIR]
ringzero vip-del --vip IP --port PORT --proto tcp|udp [--pindir DIR]
ringzero list [--pindir DIR]
ringzero stats [--watch] [--interval SEC] [--pindir DIR]
ringzero healthcheck [--interval SEC] [--timeout-ms MS] [--rise N] [--fall N] [--pindir DIR]
```

`--mac` and `--router-mac` are set by hand, not resolved through ARP. That matches how real DSR load balancers are usually set up: backends sit on a directly attached segment with known neighbors. `healthcheck` probes every backend at once with a TCP connect and treats one probe as decisive, the way upstream did. Raise `--fall` to require N consecutive failures before a backend is pulled out, so a single dropped SYN cannot reshuffle the table. UDP backends have no generic way to check reachability, so they're always treated as healthy unless you flip them with `backend-set --down`.

`vip-del` removes a VIP along with its backends; `backend-del` frees one backend id for reuse.

`--port 0` makes a VIP match every port for its protocol. There is no port to health check in that case, so those backends are left alone the same way UDP ones are.

Where `bpftool` is a wrapper that dispatches on kernel version and yours has no matching build, point `BPFTOOL` at a real one, for example `BPFTOOL=$(ls /usr/lib/linux-tools/*/bpftool | head -1)`, and pass it to both `make bpf` and `verify_datapath.py`.

Once `attach` loads the program and pins its maps under `/sys/fs/bpf/ringzero`, the CLI process can exit. The data plane keeps running with no userspace process attached. Later commands like `vip-add` just open the pinned maps directly.

## Running the local demo

You don't need a physical NIC or a second machine. `scripts/setup-netns.sh` builds a topology out of network namespaces and veth pairs: a client, a router where the XDP program attaches, and two backends.

```
sudo ./scripts/setup-netns.sh
sudo ip netns exec client ./bench/floodgen 10.99.0.1 9000 5
sudo ./zig-out/bin/ringzero stats --watch
sudo ./scripts/teardown-netns.sh
```

Watch the packet count in `ringzero stats` climb while `floodgen` runs. That's the data plane matching the VIP, hashing the flow, rewriting the packet, and redirecting it, all inside the kernel.

## Checking correctness

Each backend namespace runs a small UDP counter (`scripts/udp_sink.py`, logged to `/tmp/ringzero-backend*.log`) so you can watch packets arrive. Both backends should show counts climbing, split roughly evenly.

Getting there needs one sysctl, which the setup script sets for you. DSR delivers the packet with the *client's* source address still on it, so the backend receives traffic from 10.10.0.2 on a link with no route back to 10.10.0.2, and reverse path filtering drops it before any socket sees it. Even loose mode (`rp_filter=2`) isn't enough when there's no route to the source at all. `setup-netns.sh` sets `rp_filter=0` in the backend namespaces, which is what real DSR deployments do for the same reason. If the counters ever sit at zero, `ip netns exec backend1 nstat -az | grep ReversePathFilter` is the first thing to check.

If you want to check the data plane on its own, without your local network stack in the way, use `bpftool prog run`:

```
sudo bpftool net show                     # find the attached program's id
sudo ./scripts/verify_datapath.py --prog-id <id> \
    --vip 10.99.0.1 --vip-port 9000 --proto udp

# every flow stable, and spread across the backends
sudo ./scripts/verify_datapath.py --prog-id <id> \
    --vip 10.99.0.1 --vip-port 9000 --flows 200

# a VIP with no backends has to drop, not fall through somewhere
sudo ./scripts/verify_datapath.py --prog-id <id> \
    --vip 10.99.0.2 --vip-port 9000 --expect-action drop
```

This builds a real Ethernet, IP, and UDP packet, runs it through the loaded program, and checks that the rewritten packet has valid checksums. Add `--expect-dst` to also check which backend it went to. `bpftool prog run` lets you test a BPF program the way you'd test any function, without needing a working network path around it.

`--flows N` sends N distinct source ports, checks that the same flow always lands on the same backend every time, and prints how the flows spread across them. A single packet uses one fixed 5-tuple, so which backend it reaches is whatever the table says; pass `--expect-dst` only when you already know which one that is. `--expect-action` asserts which XDP action the program returns, so a test can prove a packet was dropped instead of only proving one was forwarded.

## About the numbers

This demo runs on veth pairs inside one kernel, processed by whatever single CPU handles that interface's one RX queue. There's no RSS spreading work across cores the way a real NIC provides. Expect low single digit millions of packets per second on a dev box, not 10 million. That ceiling belongs to this test setup, not to XDP or this code.

To get near what the project's name promises, you need what Katran actually runs on: multi-queue NICs with native XDP driver support (Mellanox mlx5, Intel i40e or ice), RSS spreading flows across many cores, and native attachment (`ringzero attach --mode native`). On real hardware you also don't need the `xdp_pass.c` workaround. That program exists only because redirecting between two veth interfaces requires both ends to have XDP enabled, which a real NIC's egress path doesn't need.

## What's missing compared to Katran

- No IPIP or GUE encapsulation. Katran usually tunnels the original packet so backends can live anywhere on the network. This project rewrites headers directly and expects backends on a directly attached segment.
- No BGP or ECMP integration. Katran's control plane announces VIPs over BGP so upstream routers can spread traffic across many LB boxes. Here, one box does the whole job.
- IPv4 only.
- Health checking is a plain TCP connect probe, not a pluggable, application-aware check.
- No CO-RE portability across kernel versions.

## License

No license yet. All rights reserved by default until one is added.
