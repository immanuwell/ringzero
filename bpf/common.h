/* common.h — layout shared between the BPF C program and the Zig control plane.
 *
 * Only fixed-width stdint types are used here (no linux/bpf.h, no vmlinux.h)
 * so this single header can be parsed both by clang -target bpf and by Zig's
 * @cImport with identical struct layout on both sides.
 */
#ifndef PROXY_COMMON_H
#define PROXY_COMMON_H

/* Deliberately not unconditionally including <stdint.h>: pulling in glibc
 * headers while compiling for -target bpf drags in multilib stub checks
 * that don't apply here. When this header is reached from userspace (Zig's
 * C importer, via libbpf.h -> stdint.h), _STDINT_H is already defined and we
 * reuse glibc's real typedefs instead of redeclaring conflicting ones. */
#ifndef _STDINT_H
typedef unsigned char      uint8_t;
typedef unsigned short     uint16_t;
typedef unsigned int       uint32_t;
typedef unsigned long long uint64_t;
#endif

#define MAX_VIPS               64
#define MAX_BACKENDS           256
#define MAX_BACKENDS_PER_VIP   32

/* Maglev lookup table size per VIP. Google's Maglev paper recommends a prime
 * at least 100x the expected backend count for good load balance; 4099 is
 * comfortably >100x MAX_BACKENDS_PER_VIP (32). */
#define MAGLEV_TABLE_SIZE      4099

#define IPPROTO_TCP_ 6
#define IPPROTO_UDP_ 17

/* Key identifying a virtual IP service: dst ip/port/proto the LB listens on.
 * vip_port == 0 means "match any port for this proto" (wildcard VIP). */
struct vip_key {
    uint32_t vip_addr; /* network byte order */
    uint16_t vip_port; /* network byte order, 0 = wildcard */
    uint8_t  proto;    /* IPPROTO_TCP / IPPROTO_UDP */
    uint8_t  pad;
};

/* Per-VIP bookkeeping: which slice of the global maglev table belongs to it. */
struct vip_info {
    uint32_t vip_id;        /* index into the maglev table: slot = vip_id*MAGLEV_TABLE_SIZE + (hash % SIZE) */
    uint32_t backend_count; /* informational, for control-plane/stats display */
};

#define BACKEND_FLAG_HEALTHY 0x1

/* A real backend server that traffic for a VIP gets DNAT'd + redirected to.
 * `vip_id`/`port`/`proto` duplicate information already implied by which VIP
 * a backend was added under; keeping them here too means the control plane
 * can reconstruct "which backends belong to this VIP" and "how do I health
 * check this backend" purely by iterating backend_map, with no side-channel
 * state file needed — the BPF map is the single source of truth. */
struct backend {
    uint32_t addr;           /* backend real IP, network byte order */
    uint8_t  mac[6];         /* backend's MAC (new dst mac) */
    uint8_t  router_mac[6];  /* our MAC on the egress link (new src mac) */
    uint32_t ifindex_egress; /* bpf_redirect() target; 0 => XDP_TX out the same ingress iface */
    uint32_t vip_id;         /* which VIP this backend serves */
    uint16_t port;           /* health-check target port, network byte order */
    uint8_t  proto;          /* IPPROTO_TCP_ / IPPROTO_UDP_ */
    uint8_t  flags;          /* BACKEND_FLAG_HEALTHY */
};

struct lb_stats {
    uint64_t packets;
    uint64_t bytes;
    uint64_t dropped;
    uint64_t passed;
};

/* stats_map index 0 is reserved for global totals; indices 1..MAX_VIPS are
 * per-VIP (vip_id + 1). */
#define STATS_GLOBAL_IDX 0

/* Sentinel stored in maglev_map slots with no assigned backend (e.g. a VIP
 * that has no healthy backends left). ARRAY maps always return a value for
 * any valid index, so we can't rely on "lookup failed" to mean "no backend"
 * — every slot must be explicitly written, and this is the "empty" value. */
#define BACKEND_ID_NONE 0xFFFFFFFFu

#endif /* PROXY_COMMON_H */
