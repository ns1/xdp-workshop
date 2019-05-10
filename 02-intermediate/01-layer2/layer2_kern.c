/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/if_ether.h>

#include "bpf_endian.h"

#include "layer2_maps.h"
#include "utils.h"

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

SEC("layer2")
int layer2_fn(struct xdp_md *ctx)
{
    __u32 action = XDP_PASS;

    __u32 nh_offset = 0;
    __u32 nh_proto = 0;

    action = parse_eth(ctx, &nh_offset, &nh_proto);
    if (action != XDP_PASS)
    {
        goto ret;
    }

ret:
    return update_action_stats(ctx, action);
}

char _license[] SEC("license") = "GPL";
