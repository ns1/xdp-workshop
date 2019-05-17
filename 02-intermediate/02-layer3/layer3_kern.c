/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>

#include "bpf_endian.h"

#include "utils.h"

#include "layer2_maps.h"
#include "layer3_maps.h"

static __always_inline __u32 parse_eth(struct xdp_md *ctx, __u32 *nh_offset, __u32 *nh_proto)
{
    void *data_end = get_data_end(ctx);
    struct ethhdr *eth = get_data(ctx) + *nh_offset;

    if (eth + 1 > data_end)
    {
        return XDP_DROP;
    }

    if (bpf_map_lookup_elem(&mac_blacklist, &eth->h_source))
    {
        return XDP_DROP;
    }

    *nh_offset += sizeof(*eth);
    *nh_proto = bpf_ntohs(eth->h_proto);

#pragma unroll
    for (int i = 0; i < 2; i++)
    {
        if (*nh_proto == ETH_P_8021Q || *nh_proto == ETH_P_8021AD)
        {
            struct vlan_hdr *vlan = get_data(ctx) + *nh_offset;
            if (vlan + 1 > data_end)
            {
                return XDP_DROP;
            }

            *nh_offset += sizeof(*vlan);
            *nh_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        }
    }

    return XDP_PASS;
}

static __always_inline __u32 parse_ipv4(struct xdp_md *ctx, __u32 *nh_offset, __u32 *nh_proto)
{
    void *data_end = get_data_end(ctx);
    struct iphdr *ip = get_data(ctx) + *nh_offset;

    struct lpm_v4_key key;

    if (ip + 1 > data_end)
    {
        return XDP_DROP;
    }

    __builtin_memcpy(key.lpm.data, &ip->saddr, sizeof(key.padding));
    key.lpm.prefixlen = 32;

    if (bpf_map_lookup_elem(&v4_blacklist, &key.lpm))
    {
        return XDP_DROP;
    }

    *nh_offset += ip->ihl * 4;
    *nh_proto = ip->protocol;

    return XDP_PASS;
}

static __always_inline __u32 parse_ipv6(struct xdp_md *ctx, __u32 *nh_offset, __u32 *nh_proto)
{
    void *data_end = get_data_end(ctx);
    struct ipv6hdr *ip = get_data(ctx) + *nh_offset;

    struct lpm_v6_key key;

    if (ip + 1 > data_end)
    {
        return XDP_DROP;
    }

    __builtin_memcpy(key.lpm.data, &ip->saddr, sizeof(key.padding));
    key.lpm.prefixlen = 128;

    if (bpf_map_lookup_elem(&v6_blacklist, &key.lpm))
    {
        return XDP_DROP;
    }

    *nh_offset += sizeof(*ip);
    // Note we are ignoring extension headers for this workshop.
    *nh_proto = ip->nexthdr;

    return XDP_PASS;
}

SEC("layer3")
int layer3_fn(struct xdp_md *ctx)
{
    __u32 action = XDP_PASS;

    __u32 nh_offset = 0;
    __u32 nh_proto = 0;

    action = parse_eth(ctx, &nh_offset, &nh_proto);
    if (action != XDP_PASS)
    {
        goto ret;
    }

    switch (nh_proto)
    {
    case ETH_P_IP:
        action = parse_ipv4(ctx, &nh_offset, &nh_proto);
        break;
    case ETH_P_IPV6:
        action = parse_ipv6(ctx, &nh_offset, &nh_proto);
        break;
    default:
        goto ret;
    }

    if (action != XDP_PASS)
    {
        goto ret;
    }

ret:
    return update_action_stats(ctx, action);
}

char _license[] SEC("license") = "GPL";
