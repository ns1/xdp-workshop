/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/if_ether.h>

#include "bpf_endian.h"

#include "utils.h"

#include "layer2_maps.h"

static __always_inline __u32 parse_eth(struct context *ctx)
{
    struct ethhdr *eth = ctx->data_start + ctx->nh_offset;

    if (eth + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    if (bpf_map_lookup_elem(&mac_blacklist, &eth->h_source))
    {
        return XDP_DROP;
    }

    ctx->nh_offset += sizeof(*eth);
    ctx->nh_proto = bpf_ntohs(eth->h_proto);

#pragma unroll
    for (int i = 0; i < 2; i++)
    {
        if (ctx->nh_proto == ETH_P_8021Q || ctx->nh_proto == ETH_P_8021AD)
        {
            struct vlan_hdr *vlan = ctx->data_start + ctx->nh_offset;
            if (vlan + 1 > ctx->data_end)
            {
                return XDP_DROP;
            }

            ctx->nh_offset += sizeof(*vlan);
            ctx->nh_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        }
    }

    return XDP_PASS;
}

SEC("layer2")
int layer2_fn(struct xdp_md *xdp_ctx)
{
    __u32 action = XDP_PASS;

    struct context ctx = to_ctx(xdp_ctx);

    action = parse_eth(&ctx);
    if (action != XDP_PASS)
    {
        goto ret;
    }

ret:
    return update_action_stats(ctx, action);
}

char _license[] SEC("license") = "GPL";
