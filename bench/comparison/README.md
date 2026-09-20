# Comparison load test: ringzero vs. NGINX vs. Envoy

Config and commands behind the chart in `media/results-10m.html`. Read that page's
callout first: this is not a benchmark of which proxy is "better." NGINX and Envoy do
TLS, HTTP routing, health checks, and observability that ringzero doesn't, and this
test gives them no credit for any of it. It only measures one thing: how many raw UDP
packets a second each one can move before something drops, with XDP skipping the
socket stack entirely and the other two going through it.

HAProxy is not in this comparison. It has no generic UDP passthrough mode, only
QUIC/HTTP-3 termination, which a raw UDP flood can't exercise.

`nginx.conf` and `envoy.yaml` here are reconstructed from the tuning this project's
maintainer actually used, not copied from the original run (NGINX and HAProxy were
installed via `apt` for testing and removed afterward; Envoy ran from a static binary
kept outside this repo). They encode the same fixes that mattered for getting a real
number instead of a collapsed one, listed below. Envoy's `udp_proxy` listener filter
schema has changed across releases, so if `envoy.yaml` doesn't load on your installed
version, check `envoy --version` and adjust the `listener_filters` section against
that version's proto.

## Topology

Same netns/veth rig as the rest of this repo's demo, see `scripts/setup-netns.sh`:

- VIP `10.99.0.1:9000/udp`
- backend1 `10.20.0.2:9000` behind `veth-b1`
- backend2 `10.30.0.2:9000` behind `veth-b2`
- client sends from the `client` netns behind `veth-c-peer`

The difference from the ringzero demo: NGINX/Envoy are normal userspace processes,
not an XDP program attached to `veth-c`, so the VIP needs a real address for the
kernel to bind a socket to. Run `setup-netns.sh` first, then skip
`ringzero attach`/`vip-add`/`backend-add` and instead:

```
sudo ip addr add 10.99.0.1/32 dev veth-c
```

## Running NGINX

```
sudo nginx -c "$(pwd)/nginx.conf" -g "daemon off;"
```

Two things matter here beyond the obvious `reuseport`/`worker_processes auto`:

- **Leave `proxy_responses` unset.** Setting it to `0` means "close the session
  after one client datagram has been proxied," not "don't wait for a response." Against
  a backend that never replies (like `scripts/udp_sink.py`), that tears down and
  rebuilds the upstream connection on every single packet and collapses throughput to
  near zero. It looks like a capacity ceiling. It's a config bug.
- **Bump `rcvbuf`/`sndbuf`** on the `listen ... udp` directive. The default UDP socket
  buffers are far too small at multi-million-pps rates.

## Running Envoy

```
sudo envoy -c "$(pwd)/envoy.yaml" --concurrency 16
```

`--concurrency` has to be passed explicitly. Envoy doesn't always infer worker count
from the host on its own.

## Sending the flood and reading the result

```
sudo ip netns exec client ./bench/floodgen 10.99.0.1 9000 15 32
```

Neither NGINX nor Envoy exposes an internal packets-forwarded counter the way
ringzero's `stats` command does, so read the result from kernel-level TX packet
counters on the backend-facing veths instead:

```
ip -s link show veth-b1
ip -s link show veth-b2
```

Watch the **TX** counter on those interfaces, not RX. Packets the proxy forwards *to*
a backend leave as TX on that backend's root-side veth; RX on the same interface is
traffic coming back *from* the backend. Reading the wrong one looks like near-zero
delivered traffic and makes a working proxy look broken.

Tear down with `sudo ./scripts/teardown-netns.sh` between runs, same as the regular
demo.
