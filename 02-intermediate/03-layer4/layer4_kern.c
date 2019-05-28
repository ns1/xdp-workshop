/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "bpf_endian.h"

#include "utils.h"

#include "layer2_maps.h"
#include "layer3_maps.h"
#include "layer4_maps.h"

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

static __always_inline __u32 parse_ipv4(struct context *ctx)
{
    struct iphdr *ip = ctx->data_start + ctx->nh_offset;

    struct lpm_v4_key key;

    if (ip + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    __builtin_memcpy(key.lpm.data, &ip->saddr, sizeof(key.padding));
    key.lpm.prefixlen = 32;

    if (bpf_map_lookup_elem(&v4_blacklist, &key.lpm))
    {
        return XDP_DROP;
    }

    ctx->nh_offset += ip->ihl * 4;
    ctx->nh_proto = ip->protocol;

    return XDP_PASS;
}

static __always_inline __u32 parse_ipv6(struct context *ctx)
{
    struct ipv6hdr *ip = ctx->data_start + ctx->nh_offset;

    struct lpm_v6_key key;

    if (ip + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    __builtin_memcpy(key.lpm.data, &ip->saddr, sizeof(key.padding));
    key.lpm.prefixlen = 128;

    if (bpf_map_lookup_elem(&v6_blacklist, &key.lpm))
    {
        return XDP_DROP;
    }

    ctx->nh_offset += sizeof(*ip);
    // Note we are ignoring extension headers for this workshop.
    ctx->nh_proto = ip->nexthdr;

    return XDP_PASS;
}

static __always_inline __u32 parse_udp(struct context *ctx)
{
    struct udphdr *udp = ctx->data_start + ctx->nh_offset;

    if (udp + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    struct port_key src_key = {
        .type = source_port,
    };
    struct port_key dst_key = {
        .type = destination_port,
    };

    src_key.port = bpf_ntohs(udp->source);
    dst_key.port = bpf_ntohs(udp->dest);

    if (bpf_map_lookup_elem(&udp_port_blacklist, &src_key) ||
        bpf_map_lookup_elem(&udp_port_blacklist, &dst_key))
    {
        return XDP_DROP;
    }

    return XDP_PASS;
}

static __always_inline __u32 parse_tcp(struct context *ctx)
{
    struct tcphdr *tcp = ctx->data_start + ctx->nh_offset;

    if (tcp + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    struct port_key src_key = {
        .type = source_port,
    };
    struct port_key dst_key = {
        .type = destination_port,
    };

    src_key.port = bpf_ntohs(tcp->source);
    dst_key.port = bpf_ntohs(tcp->dest);

    if (bpf_map_lookup_elem(&tcp_port_blacklist, &src_key) ||
        bpf_map_lookup_elem(&tcp_port_blacklist, &dst_key))
    {
        return XDP_DROP;
    }

    return XDP_PASS;
}

SEC("layer4")
int layer4_fn(struct xdp_md *xdp_ctx)
{
    __u32 action = XDP_PASS;

    struct context ctx = to_ctx(xdp_ctx);

    action = parse_eth(&ctx);
    if (action != XDP_PASS)
    {
        goto ret;
    }

    switch (ctx.nh_proto)
    {
    case ETH_P_IP:
        action = parse_ipv4(&ctx);
        break;
    case ETH_P_IPV6:
        action = parse_ipv6(&ctx);
        break;
    default:
        goto ret;
    }

    if (action != XDP_PASS)
    {
        goto ret;
    }

    switch (ctx.nh_proto)
    {
    case IPPROTO_UDP:
        action = parse_udp(&ctx);
        break;
    case IPPROTO_TCP:
        action = parse_tcp(&ctx);
        break;
    default:
        goto ret;
    }

ret:
    return update_action_stats(&ctx, action);
}

char _license[] SEC("license") = "GPL";
