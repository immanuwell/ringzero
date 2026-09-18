// SPDX-License-Identifier: GPL-2.0
/*
 * xdp_lb.c — the entire proxy's data plane.
 *
 * This program is attached to the XDP hook of a NIC (or veth, for the local
 * demo) and runs *before* the kernel builds an sk_buff for the packet. For
 * every packet it:
 *
 *   1. Parses Ethernet/IPv4/{TCP,UDP} headers with explicit bounds checks
 *      (required by the verifier — there is no packet buffer safety net
 *      here, we prove safety at compile time).
 *   2. Looks up the destination (VIP) in `vip_map`. Traffic that isn't for
 *      one of our virtual IPs is passed straight to the kernel (XDP_PASS) —
 *      this program is a transparent bump-in-the-wire for anything else
 *      running on the box.
 *   3. Picks a backend for the flow using a per-VIP Maglev consistent-hash
 *      lookup table (`maglev_map`), so all packets belonging to the same
 *      5-tuple land on the same backend even as the backend set changes.
 *   4. Rewrites the destination MAC/IP to the chosen backend (DNAT, no port
 *      translation — this is a DSR-style load balancer, same design Katran
 *      uses at Facebook) and redirects the packet out towards that backend
 *      with bpf_redirect(), or XDP_TX's it back out the same interface.
 *   5. Updates per-CPU packet/byte counters.
 *
 * Everything happens without a single memory allocation, context switch, or
 * copy — that's the whole reason this design can push tens of millions of
 * packets/sec on real multi-queue NICs: the driver's poll loop hands us the
 * raw frame directly out of the RX ring.
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";

#define ETH_P_IP 0x0800

/* Offset bits of iph->frag_off plus MF. DF (0x4000) stays outside it, so
 * ordinary don't-fragment traffic is unaffected. */
#define IP_FRAG_MASK 0x3fff

/* ---- Maps -------------------------------------------------------------- */

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_VIPS);
    __type(key, struct vip_key);
    __type(value, struct vip_info);
} vip_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_BACKENDS);
    __type(key, __u32); /* backend id */
    __type(value, struct backend);
} backend_map SEC(".maps");

/* Flat maglev table: index = vip_id * MAGLEV_TABLE_SIZE + slot -> backend id. */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_VIPS * MAGLEV_TABLE_SIZE);
    __type(key, __u32);
    __type(value, __u32);
} maglev_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_VIPS + 1);
    __type(key, __u32);
    __type(value, struct lb_stats);
} stats_map SEC(".maps");

/* ---- Helpers ------------------------------------------------------------ */

static __always_inline void bump_stats(__u32 idx, __u32 bytes, __u8 dropped)
{
    struct lb_stats *s = bpf_map_lookup_elem(&stats_map, &idx);
    if (!s)
        return;
    if (dropped) {
        s->dropped += 1;
    } else {
        s->packets += 1;
        s->bytes += bytes;
    }
}

static __always_inline void bump_passed(void)
{
    __u32 idx = STATS_GLOBAL_IDX;
    struct lb_stats *s = bpf_map_lookup_elem(&stats_map, &idx);
    if (s)
        s->passed += 1;
}

/* 32-bit FNV-1a — cheap, good-enough flow hash for consistent hashing. It
 * only needs to be uniform and stable per-flow, not cryptographically
 * anything. */
static __always_inline __u32 flow_hash(__u32 saddr, __u32 daddr, __u16 sport,
                                        __u16 dport, __u8 proto)
{
    __u32 h = 2166136261u;
#define MIX(byte) h = (h ^ (byte)) * 16777619u
    MIX(saddr & 0xff); MIX((saddr >> 8) & 0xff); MIX((saddr >> 16) & 0xff); MIX((saddr >> 24) & 0xff);
    MIX(daddr & 0xff); MIX((daddr >> 8) & 0xff); MIX((daddr >> 16) & 0xff); MIX((daddr >> 24) & 0xff);
    MIX(sport & 0xff); MIX((sport >> 8) & 0xff);
    MIX(dport & 0xff); MIX((dport >> 8) & 0xff);
    MIX(proto);
#undef MIX
    return h;
}

static __always_inline __u16 csum_fold_helper(__u32 csum)
{
    csum = (csum & 0xffff) + (csum >> 16);
    csum = (csum & 0xffff) + (csum >> 16);
    return (__u16)~csum;
}

/* Incrementally patch a checksum for a single changed 32-bit field (RFC
 * 1071/1624 style), used for both the IPv4 header checksum and the L4
 * pseudo-header checksum after a DNAT rewrite. */
static __always_inline __u16 csum_diff4(__be32 from, __be32 to, __u16 old_csum)
{
    __u32 csum = bpf_csum_diff(&from, 4, &to, 4, ~old_csum & 0xffff);
    return csum_fold_helper(csum);
}

/* ---- Main program -------------------------------------------------------- */

SEC("xdp")
int xdp_lb_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) {
        bump_passed();
        return XDP_PASS;
    }

    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        bump_passed();
        return XDP_PASS; /* only IPv4 handled by this demo */
    }

    struct iphdr *iph = (void *)(eth + 1);
    if ((void *)(iph + 1) > data_end) {
        bump_passed();
        return XDP_PASS;
    }
    if (iph->ihl < 5) {
        bump_stats(STATS_GLOBAL_IDX, 0, 1);
        return XDP_DROP;
    }

    /* Only the first fragment carries L4 ports, and sending it to a backend
     * while the rest goes to the kernel just strands both halves. Leave the
     * whole datagram to the kernel. */
    if (iph->frag_off & bpf_htons(IP_FRAG_MASK)) {
        bump_passed();
        return XDP_PASS;
    }

    /* IP options are fine; ihl just moves where L4 starts. */
    void *l4 = (void *)iph + (iph->ihl * 4);
    if (l4 > data_end) {
        bump_passed();
        return XDP_PASS;
    }

    __u16 sport = 0, dport = 0;
    struct tcphdr *tcph = NULL;
    struct udphdr *udph = NULL;

    if (iph->protocol == IPPROTO_TCP_) {
        tcph = l4;
        if ((void *)(tcph + 1) > data_end) {
            bump_passed();
            return XDP_PASS;
        }
        sport = tcph->source;
        dport = tcph->dest;
    } else if (iph->protocol == IPPROTO_UDP_) {
        udph = l4;
        if ((void *)(udph + 1) > data_end) {
            bump_passed();
            return XDP_PASS;
        }
        sport = udph->source;
        dport = udph->dest;
    } else {
        bump_passed();
        return XDP_PASS;
    }

    /* 1. Exact vip match (addr+port+proto), then wildcard-port match. */
    struct vip_key key = {
        .vip_addr = iph->daddr,
        .vip_port = dport,
        .proto = iph->protocol,
    };
    struct vip_info *vip = bpf_map_lookup_elem(&vip_map, &key);
    if (!vip) {
        key.vip_port = 0;
        vip = bpf_map_lookup_elem(&vip_map, &key);
    }
    if (!vip) {
        bump_passed();
        return XDP_PASS; /* not our traffic */
    }

    /* 2. Consistent-hash the flow to a backend via this VIP's maglev slice. */
    __u32 h = flow_hash(iph->saddr, iph->daddr, sport, dport, iph->protocol);
    __u32 slot = h % MAGLEV_TABLE_SIZE;
    __u32 mkey = vip->vip_id * MAGLEV_TABLE_SIZE + slot;
    __u32 *backend_id = bpf_map_lookup_elem(&maglev_map, &mkey);
    if (!backend_id || *backend_id == BACKEND_ID_NONE) {
        bump_stats(vip->vip_id + 1, 0, 1);
        bump_stats(STATS_GLOBAL_IDX, 0, 1);
        return XDP_DROP;
    }

    struct backend *be = bpf_map_lookup_elem(&backend_map, backend_id);
    if (!be || !(be->flags & BACKEND_FLAG_HEALTHY)) {
        bump_stats(vip->vip_id + 1, 0, 1);
        bump_stats(STATS_GLOBAL_IDX, 0, 1);
        return XDP_DROP;
    }

    /* 3. DNAT rewrite: dst IP -> backend real IP, dst/src MAC -> backend/us.
     *    Port is left untouched (DSR-style, no port translation). */
    __be32 old_daddr = iph->daddr;
    __be32 new_daddr = be->addr;

    __u16 new_ip_csum = csum_diff4(old_daddr, new_daddr, iph->check);
    iph->daddr = new_daddr;
    iph->check = new_ip_csum;

    if (tcph) {
        __u16 new_csum = csum_diff4(old_daddr, new_daddr, tcph->check);
        tcph->check = new_csum;
    } else if (udph && udph->check != 0) {
        __u16 new_csum = csum_diff4(old_daddr, new_daddr, udph->check);
        udph->check = new_csum ? new_csum : 0xffff;
    }

    __builtin_memcpy(eth->h_dest, be->mac, 6);
    __builtin_memcpy(eth->h_source, be->router_mac, 6);

    __u32 pkt_len = (__u32)(data_end - data);
    bump_stats(vip->vip_id + 1, pkt_len, 0);
    bump_stats(STATS_GLOBAL_IDX, pkt_len, 0);

    if (be->ifindex_egress != 0)
        return bpf_redirect(be->ifindex_egress, 0);
    return XDP_TX;
}
