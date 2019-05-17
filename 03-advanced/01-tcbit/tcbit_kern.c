/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/in.h>
#include <linux/in6.h>

#include "bpf_endian.h"

#include "utils.h"

#define bpf_debug(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

static __always_inline __u32 parse_eth(struct xdp_md *ctx, struct metadata *meta)
{
    void *data_end = get_data_end(ctx);
    meta->eth = get_data(ctx) + meta->nh_offset;

    if (meta->eth + 1 > data_end)
    {
        return XDP_DROP;
    }

    meta->nh_offset += sizeof(struct ethhdr);
    meta->nh_proto = bpf_ntohs(meta->eth->h_proto);

#pragma unroll
    for (int i = 0; i < MAX_VLAN_DEPTH; i++)
    {
        if (meta->nh_proto == ETH_P_8021Q || meta->nh_proto == ETH_P_8021AD)
        {
            struct vlan_hdr *vlan = get_data(ctx) + meta->nh_offset;
            if (vlan + 1 > data_end)
            {
                return XDP_DROP;
            }

            meta->nh_offset += sizeof(*vlan);
            meta->nh_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        }
        return XDP_CONTINUE;
    }

    return XDP_CONTINUE;
}

static __always_inline __u32 parse_v4(struct xdp_md *ctx, struct metadata *meta)
{
    void *data_end = get_data_end(ctx);
    meta->v4 = get_data(ctx) + meta->nh_offset;

    if (meta->v4 + 1 > data_end)
    {
        return XDP_DROP;
    }

    meta->nh_offset += meta->v4->ihl * 4;
    meta->nh_proto = meta->v4->protocol;

    return XDP_CONTINUE;
}

static __always_inline __u32 parse_v6(struct xdp_md *ctx, struct metadata *meta)
{
    void *data_end = get_data_end(ctx);
    meta->v6 = get_data(ctx) + meta->nh_offset;

    if (meta->v6 + 1 > data_end)
    {
        return XDP_DROP;
    }

    meta->nh_offset += sizeof(struct ipv6hdr);
    meta->nh_proto = meta->v6->nexthdr;

    return XDP_CONTINUE;
}

static __always_inline __u32 parse_udp(struct xdp_md *ctx, struct metadata *meta)
{
    void *data_end = get_data_end(ctx);
    meta->udp = get_data(ctx) + meta->nh_offset;

    if (meta->udp + 1 > data_end)
    {
        return XDP_DROP;
    }

    meta->nh_offset += sizeof(struct udphdr);

    if (bpf_ntohs(meta->udp->dest) == 53)
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

static __always_inline void swap_mac(struct metadata *meta)
{
    __u8 temp[6];
    __builtin_memcpy(temp, meta->eth->h_dest, sizeof(temp));
    __builtin_memcpy(meta->eth->h_dest, meta->eth->h_source, sizeof(temp));
    __builtin_memcpy(meta->eth->h_source, temp, sizeof(temp));
}

static __always_inline void swap_ip(struct metadata *meta)
{
    if (meta->v4)
    {
        __be32 temp;
        __builtin_memcpy(&temp, &meta->v4->daddr, sizeof(temp));
        __builtin_memcpy(&meta->v4->daddr, &meta->v4->saddr, sizeof(temp));
        __builtin_memcpy(&meta->v4->saddr, &temp, sizeof(temp));

        __u8 old_ttl = meta->v4->ttl;
        meta->v4->ttl = 64;

        csum_update(&meta->v4->check, old_ttl, meta->v4->ttl);
    }
    else if (meta->v6)
    {
        struct in6_addr temp;
        __builtin_memcpy(&temp, &meta->v6->daddr, sizeof(temp));
        __builtin_memcpy(&meta->v6->daddr, &meta->v6->saddr, sizeof(temp));
        __builtin_memcpy(&meta->v6->saddr, &temp, sizeof(temp));

        meta->v6->hop_limit = 64;
    }
}

static __always_inline void swap_ports(struct metadata *meta)
{
    __be16 temp;
    __builtin_memcpy(&temp, &meta->udp->dest, sizeof(temp));
    __builtin_memcpy(&meta->udp->dest, &meta->udp->source, sizeof(temp));
    __builtin_memcpy(&meta->udp->source, &temp, sizeof(temp));
}

SEC("tcbit")
int tcbit_fn(struct xdp_md *ctx)
{
    struct metadata meta = {
        .nh_offset = 0,
        .nh_proto = 0,
    };

    int action = parse_eth(ctx, &meta);
    if (action != XDP_CONTINUE)
    {
        goto ret;
    }

    switch (meta.nh_proto)
    {
    case ETH_P_IP:
        action = parse_v4(ctx, &meta);
        break;
    case ETH_P_IPV6:
        action = parse_v6(ctx, &meta);
        break;
    default:
        action = XDP_PASS;
    }

    if (action != XDP_CONTINUE)
    {
        goto ret;
    }

    switch (meta.nh_proto)
    {
    case IPPROTO_UDP:
        action = parse_udp(ctx, &meta);
        break;
    default:
        action = XDP_PASS;
    }

    if (action != XDP_CONTINUE)
    {
        goto ret;
    }

    void *data_end = get_data_end(ctx);
    meta.dns = get_data(ctx) + meta.nh_offset;
    meta.dns_compare = get_data(ctx) + meta.nh_offset;

    if (meta.dns + 1 > data_end)
    {
        action = XDP_PASS;
        goto ret;
    }

    __u16 old_flags = meta.dns_compare->flags;

    meta.dns->qr = 1;
    meta.dns->opcode = 0;
    meta.dns->aa = 0;
    meta.dns->tc = 1;
    meta.dns->ra = 1;

    csum_update(&meta.udp->check, old_flags, meta.dns_compare->flags);

    swap_mac(&meta);
    swap_ip(&meta);
    swap_ports(&meta);

    action = XDP_TX;
ret:
    return update_action_stats(ctx, action);
}

char _license[] SEC("license") = "GPL";
