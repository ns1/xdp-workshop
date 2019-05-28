#ifndef _XDPFW_KERN_L2_H
#define _XDPFW_KERN_L2_H

#include <linux/if_ether.h>

/*
    Pulled from $(LINUX)/include/linux/if_vlan.h#L38

    This is used for unwrapping vlan headers if any exist in the packet. This is NOT my code in anyway and is directly
    copied from the above mentioned file in the linux kernel, which can't be directly included.
*/
struct vlan_hdr
{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

/*
    This define represents the total number of MAC addresses we are allowing to be blacklisted at any one time.

    There is technically no upper bound on this number, other than the amount of memory you are willing to dedicate
    to this blacklist.
*/
#ifndef MAC_BLACKLIST_MAX_ENTRIES
#define MAC_BLACKLIST_MAX_ENTRIES 4096
#endif

/*
    'mac_blacklist' here represents the various MAC addresses we wish to drop, and is of type 'BPF_MAP_TYPE_HASH'.
    This is the first time we have interacted with a HASH variant of a BPF map. And it comes with some additional
    things to keep in mind.

    First off notice that we have a new field 'map_flags' we are specifying bellow as opposed to when we were defining the,
    'BPF_MAP_TYPE_ARRAY' and 'BPF_MAP_TYPE_PERCPU_ARRAY' maps in the previous sections. The field in question controls
    how the kernel initializes the map itself. In this case we pass in the flag 'BPF_F_NO_PREALLOC' which means the kernel
    will not prepopulate the map with entires for each of the entires up to 'max_entries'. This important because if we did
    not specify this flag the entire map would be filled with data as soon as we loaded the program.

    Another thing of note here, is that we are _not_ using a PERCPU vairant of the 'BPF_MAP_TYPE_HASH' map, because we don't
    actually update the entries contained within the map from the kernel. We are just looking for the existence of a given
    MAC address in this map so there is no need to worry about locking in this case. This also significantly reduces the memory
    requirements of manging this map.

    Lastly we are specifying a 'value_size' of 1 here because, as previously mentioned, we are going to specifically using this
    map to test for existance, and therefore as a boolean value to trigger dropping or accepting a packet for further processing.
*/
struct bpf_map_def SEC("maps") mac_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = ETH_ALEN,
    .value_size = 1,
    .max_entries = MAC_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

/*
    'parse_eth' handles parsing the passed in packets ethernet and vlan headers if any exist. It will parse out the source MAC address
    of this packet and check to see if it exists in the 'mac_blacklist' BPF map defined above, and also unwrap up to two vlan headers.
*/
static __always_inline __u32 parse_eth(struct context *ctx)
{
    /*
        We need to access the ethernet header data so we can find out whether or not this packets source MAC address is blacklisted,
        and if not what the next protocol in the header is to continue parsing.

        So we take the pre-casted data start location pointer and adds the next header offset, which in this case is always 0.
    */
    struct ethhdr *eth = ctx->data_start + ctx->nh_offset;

    /*
        As always since we are accessing data within the packet we need to ensure that at the very least we have one entire ethernet
        header to work with.

        So take the 'eth' value and add 1 to it to see if the resulting pointer location which would be at this point:
            data_start + sizeof(struct ethhdr)
        is past the data_end pointer.
    */
    if (eth + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    /*
        Once we know we have at least a full ethernet header lets see if we have a matching source MAC address in our mac_blacklist map
        defined above. If one exists immediately return XDP_DROP and drop this packet.
    */
    if (bpf_map_lookup_elem(&mac_blacklist, &eth->h_source))
    {
        return XDP_DROP;
    }

    /*
        Give the current packets source MAC address is not present in the blacklist update the offset to the next header in line and update
        the next headers protocol to the protocol contained in the ethernet header.
    */
    ctx->nh_offset += sizeof(*eth);
    ctx->nh_proto = bpf_ntohs(eth->h_proto);

    /*
        This is the first time we are going to use a 'loop' in XDP which is generally forbidden, specifically backwards jumps being forbidden in any
        BPF program not just XDP.

        We are using a C/C++ trick where we are telling the compiler to 'unroll' this loop into its representative executions inside of the loop. This
        only works for loops that have pre-defined beginning and end points. Meaning you can't use the packet data or BPF map data to control the loop itself,
        and only works on 'small' loops in that you are still bound by the total instruction count of 4096.

        This loop is going to attempt to unroll vlan headers as there could be potentially multiple layers of vlan headers contained in a packet.
    */
#pragma unroll
    for (int i = 0; i < 2; i++)
    {
        /*
            Check to see if the next in this packet is a vlan header, i.e. either a 8021Q or 8021AD protocol header.
        */
        if (ctx->nh_proto == ETH_P_8021Q || ctx->nh_proto == ETH_P_8021AD)
        {
            /*
                Preform the same process as the raw ethernet header above to ensure get to the next header.
            */
            struct vlan_hdr *vlan = ctx->data_start + ctx->nh_offset;

            /*
                You will see this particular snippet of code over and over and over again throughout all XDP/eBPF programs.
            */
            if (vlan + 1 > ctx->data_end)
            {
                return XDP_DROP;
            }

            ctx->nh_offset += sizeof(*vlan);
            ctx->nh_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        }
    }

    /*
        If we got here we are continuing on to the next parser so return XDP_PASS.
    */
    return XDP_PASS;
}

#endif // _XDPFW_KERN_L2_H