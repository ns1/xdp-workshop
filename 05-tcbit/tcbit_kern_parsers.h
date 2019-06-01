// SPDX-License-Identifier: GPL-2.0

#ifndef _TCBIT_KERN_PARSERS_H
#define _TCBIT_KERN_PARSERS_H

#include <linux/bpf.h>

#include "kernel/bpf_helpers.h"

static __always_inline __u32 parse_eth(struct context *ctx)
{
    ctx->eth = ctx->data_start + ctx->nh_offset;

    if (ctx->eth + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    ctx->nh_offset += sizeof(struct ethhdr);
    ctx->nh_proto = bpf_ntohs(ctx->eth->h_proto);

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
        return XDP_CONTINUE;
    }

    return XDP_CONTINUE;
}

static __always_inline __u32 parse_v4(struct context *ctx)
{
    ctx->v4 = ctx->data_start + ctx->nh_offset;

    if (ctx->v4 + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    ctx->nh_offset += ctx->v4->ihl * 4;
    ctx->nh_proto = ctx->v4->protocol;

    return XDP_CONTINUE;
}

static __always_inline __u32 parse_v6(struct context *ctx)
{
    ctx->v6 = ctx->data_start + ctx->nh_offset;

    if (ctx->v6 + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    ctx->nh_offset += sizeof(struct ipv6hdr);
    ctx->nh_proto = ctx->v6->nexthdr;

    return XDP_CONTINUE;
}

static __always_inline __u32 parse_udp(struct context *ctx)
{
    ctx->udp = ctx->data_start + ctx->nh_offset;

    if (ctx->udp + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    ctx->nh_offset += sizeof(struct udphdr);

    if (bpf_ntohs(ctx->udp->dest) == 53)
    {
        return XDP_CONTINUE;
    }

    return XDP_PASS;
}

#endif // _TCBIT_KERN_PARSERS_H