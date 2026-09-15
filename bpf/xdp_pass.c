// SPDX-License-Identifier: GPL-2.0
/* Trivial pass-through XDP program. Its only purpose is to be loaded on a
 * veth's peer so that veth's native-mode redirect (ndo_xdp_xmit) has an
 * XDP-enabled receive queue to redirect into -- see the README's "native
 * mode on veth" note. */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "GPL";

SEC("xdp")
int xdp_pass_prog(struct xdp_md *ctx)
{
    (void)ctx;
    return XDP_PASS;
}
