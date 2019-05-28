#ifndef _XDPFW_KERN_L3_H
#define _XDPFW_KERN_L3_H

#include <linux/ip.h>
#include <linux/ipv6.h>

/*
    This define represents the total number of IPv4 address ranges we are allowing to be blacklisted at any one time.

    There is technically no upper bound on this number, other than the amount of memory you are willing to dedicate
    to this blacklist.
*/
#ifndef V4_BLACKLIST_MAX_ENTRIES
#define V4_BLACKLIST_MAX_ENTRIES 10000
#endif

/*
    This define represents the total number of IPv6 address ranges we are allowing to be blacklisted at any one time.

    There is technically no upper bound on this number, other than the amount of memory you are willing to dedicate
    to this blacklist.
*/
#ifndef V6_BLACKLIST_MAX_ENTRIES
#define V6_BLACKLIST_MAX_ENTRIES 10000
#endif

/*
    'v4_blacklist' here represenst the various IPv4 ranges we want to drop, and is of type 'BPF_MAP_TYPE_LPM_TRIE' which
    is a specialized BPF map type for longest prefix matching on keys. This map type is interacted with the same way as
    any other BPF map but the key matching is different in that it is capable of "ranging" matching against passed in values.
    The actual algorithm isn't important for the purposes of this workshop. However it allows for matching a packets ip address,
    say '192.168.0.1' against a range containing that IP address say '192.168.0.0/24' while not matching against the range
    '192.168.1.0/24'. This is incredibly useful in the context of XDP and DDoS mitigation because generally you don't want to
    only drop a specific address but a range of addresses.

    Other than the algorithm its important to note that the key structure here needs to be of a specific ordering specifically:
        struct bpf_lpm_trie_key {
            __u32	prefixlen;	// up to 32 for AF_INET, 128 for AF_INET6
            __u8	data[0];	// Arbitrary size
        };

    We aren't using the above structure which is defined in the kernel sources, because XDP requires fixed sized structures, i.e.
    we can't allocate memory on our own. So the key values bellow are defined in common.h with a fixed size so we can easily use
    them in this program.
*/
struct bpf_map_def SEC("maps") v4_blacklist = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct lpm_v4_key),
    .value_size = 1,
    .max_entries = V4_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

/*
    'v6_blacklist' here represens the various IPv6 ranges we want to drop, and is of the type 'BPF_MAP_TYPE_LPM_TRIE' and other than
    the 'key_size' is otherwise identical to the 'v4_blacklist' above.

    We could in theory use a single map for both IPv4 and IPv6 however, there could be collisions between IPv4/v6 ranges we want to
    blacklist.
*/
struct bpf_map_def SEC("maps") v6_blacklist = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = sizeof(struct lpm_v6_key),
    .value_size = 1,
    .max_entries = V6_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

/*
    'parse_ipv4' handles parsing the passed in packets IPv4 header. It will parse out the source address of the
    packets and check to see if it exists in the 'v4_blacklist' BPF map defined above.
*/
static __always_inline __u32 parse_ipv4(struct context *ctx)
{
    /*
        We need to access the IPv4 header data so we can find out whether or not this packets source IP address is blacklisted,
        and if not what the next protocol in the header is to continue parsing.

        So we take the pre-casted data start location pointer and adds the next header offset, which is determined in the previously
        called parse_eth function call.
    */
    struct iphdr *ip = ctx->data_start + ctx->nh_offset;

    /*
        As always since we are accessing data within the packet we need to ensure that we aren't going out of bounds.
    */
    if (ip + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    /*
        We need a copy of our 'lpm_v4_key' structure in order to query our 'v4_blacklist', we can't use the 'bpf_lpm_trie_key' struct
        directly because its 'data' field is of size 0 and we can't call alloca/malloc/etc inside an XDP program. So we need a fixed size
        structure here.
    */
    struct lpm_v4_key key;

    /*
        In order to properly match against the stored IPv4 ranges in the 'v4_blacklist' map defined above, we need to copy the
        source address in the packet to our key's 'address' field. Also because we are taking a full IPv4 address here to use as
        the key we need to set the 'prefixlen' to 32, which is the maximum size of an IPv4 address.
    */
    __builtin_memcpy(key.address, &ip->saddr, sizeof(key.address));
    key.prefixlen = 32;

    /*
        Using a LPM_TRIE is done the same way as any other map and the actual magic is done under the hood to handle matching on
        the longest prefix that exists in the trie.

        If a match does exist in our blacklist exit immediately and drop the packet.
    */
    if (bpf_map_lookup_elem(&v4_blacklist, &key))
    {
        return XDP_DROP;
    }

    /*
        Just as in the case with the ethernet header, if this packets source IP address is not matched in the blacklist we need to
        update the offset to the next header in the packet, and update the protocol of next header in the packet.
    */
    ctx->nh_offset += ip->ihl * 4;
    ctx->nh_proto = ip->protocol;

    /*
        If we got here we are continuing on to the next parser so return XDP_PASS.
    */
    return XDP_PASS;
}

/*
    'parse_ipv6' handles parsing the passed in packets IPv8 header. It will parse out the source address of the
    packets and check to see if it exists in the 'v6_blacklist' BPF map defined above.
*/
static __always_inline __u32 parse_ipv6(struct context *ctx)
{
    /*
        We need to access the IPv6 header data so we can find out whether or not this packets source IP address is blacklisted,
        and if not what the next protocol in the header is to continue parsing.

        So we take the pre-casted data start location pointer and adds the next header offset, which is determined in the previously
        called parse_eth function call.
    */
    struct ipv6hdr *ip = ctx->data_start + ctx->nh_offset;

    /*
        As always since we are accessing data within the packet we need to ensure that we aren't going out of bounds.
    */
    if (ip + 1 > ctx->data_end)
    {
        return XDP_DROP;
    }

    /*
        We need a copy of our 'lpm_v6_key' structure in order to query our 'v6_blacklist', we can't use the 'bpf_lpm_trie_key' struct
        directly because its 'data' field is of size 0 and we can't call alloca/malloc/etc inside an XDP program. So we need a fixed size
        structure here.
    */
    struct lpm_v6_key key;

    /*
        In order to properly match against the stored IPv6 ranges in the 'v6_blacklist' map defined above, we need to copy the
        source address in the packet to our key's 'address' field. Also because we are taking a full IPv6 address here to use as
        the key we need to set the 'prefixlen' to 128, which is the maximum size of an IPv6 address.
    */
    __builtin_memcpy(key.address, &ip->saddr, sizeof(key.address));
    key.prefixlen = 128;

    /*
        Using a LPM_TRIE is done the same way as any other map and the actual magic is done under the hood to handle matching on
        the longest prefix that exists in the trie.

        If a match does exist in our blacklist exit immediately and drop the packet.
    */
    if (bpf_map_lookup_elem(&v6_blacklist, &key))
    {
        return XDP_DROP;
    }

    /*
        Just as in the case with the ethernet header, if this packets source IP address is not matched in the blacklist we need to
        update the offset to the next header in the packet, and update the protocol of next header in the packet.

        Note for the purposes of this workshop we are ignoring IPv6 extension headers.
    */
    ctx->nh_offset += sizeof(*ip);
    ctx->nh_proto = ip->nexthdr;

    /*
        If we got here we are continuing on to the next parser so return XDP_PASS.
    */
    return XDP_PASS;
}

#endif // _XDPFW_KERN_L3_H