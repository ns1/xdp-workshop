/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/in.h>
#include <linux/in6.h>

#include "bpf_endian.h"

#include "utils.h"

#define bpf_debug(fmt, ...)                                        \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

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

static __always_inline void csum_update(__u16 *csum, __u32 from, __u32 to)
{
    __u32 sum, csum_c, from_c, res, res2, ret, ret2;

    csum_c = ~((__u32)*csum);
    from_c = ~from;
    res = csum_c + from_c;
    ret = res + (res < from_c);

    res2 = ret + to;
    ret2 = res2 + (res2 < to);

    sum = ret2;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    *csum = (__u16)~sum;
}

static __always_inline void swap_mac(struct context *ctx)
{
    __u8 temp[6];
    __builtin_memcpy(temp, ctx->eth->h_dest, sizeof(temp));
    __builtin_memcpy(ctx->eth->h_dest, ctx->eth->h_source, sizeof(temp));
    __builtin_memcpy(ctx->eth->h_source, temp, sizeof(temp));
}

static __always_inline void swap_ip(struct context *ctx)
{
    if (ctx->v4)
    {
        __be32 temp;
        __builtin_memcpy(&temp, &ctx->v4->daddr, sizeof(temp));
        __builtin_memcpy(&ctx->v4->daddr, &ctx->v4->saddr, sizeof(temp));
        __builtin_memcpy(&ctx->v4->saddr, &temp, sizeof(temp));

        __u8 old_ttl = ctx->v4->ttl;
        ctx->v4->ttl = 64;

        csum_update(&ctx->v4->check, old_ttl, ctx->v4->ttl);
    }
    else if (ctx->v6)
    {
        struct in6_addr temp;
        __builtin_memcpy(&temp, &ctx->v6->daddr, sizeof(temp));
        __builtin_memcpy(&ctx->v6->daddr, &ctx->v6->saddr, sizeof(temp));
        __builtin_memcpy(&ctx->v6->saddr, &temp, sizeof(temp));

        ctx->v6->hop_limit = 64;
    }
}

static __always_inline void swap_ports(struct context *ctx)
{
    __be16 temp;
    __builtin_memcpy(&temp, &ctx->udp->dest, sizeof(temp));
    __builtin_memcpy(&ctx->udp->dest, &ctx->udp->source, sizeof(temp));
    __builtin_memcpy(&ctx->udp->source, &temp, sizeof(temp));
}

SEC("tcbit")
int tcbit_fn(struct xdp_md *xdp_ctx)
{
    struct context ctx = to_ctx(xdp_ctx);

    int action = parse_eth(&ctx);
    if (action != XDP_CONTINUE)
    {
        goto ret;
    }

    switch (ctx.nh_proto)
    {
    case ETH_P_IP:
        action = parse_v4(&ctx);
        break;
    case ETH_P_IPV6:
        action = parse_v6(&ctx);
        break;
    default:
        action = XDP_PASS;
    }

    if (action != XDP_CONTINUE)
    {
        goto ret;
    }

    switch (ctx.nh_proto)
    {
    case IPPROTO_UDP:
        action = parse_udp(&ctx);
        break;
    default:
        action = XDP_PASS;
    }

    if (action != XDP_CONTINUE)
    {
        goto ret;
    }

    ctx.dns = ctx.data_start + ctx.nh_offset;

    if (ctx.dns + 1 > ctx.data_end)
    {
        action = XDP_PASS;
        goto ret;
    }

    __u16 old_flags = ctx.dns->flags.data;

    ctx.dns->flags.bits.qr = 1;
    ctx.dns->flags.bits.opcode = 0;
    ctx.dns->flags.bits.aa = 0;
    ctx.dns->flags.bits.tc = 1;
    ctx.dns->flags.bits.ra = 1;

    csum_update(&ctx.udp->check, old_flags, ctx.dns->flags.data);

    swap_mac(&ctx);
    swap_ip(&ctx);
    swap_ports(&ctx);

    action = XDP_TX;
ret:
    return update_action_stats(&ctx, action);
}

char _license[] SEC("license") = "GPL";
