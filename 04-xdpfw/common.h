// SPDX-License-Identifier: GPL-2.0

#ifndef _COMMON_H
#define _COMMON_H

#include <linux/types.h>

/*
    'context' here is the struct we will be passing around between the parsing functions in this XDP program,
    and is responsible for tracking where we are in the packet via 'nh_offset' as well as what the next headers
    protocol is via 'nh_proto'.

    This struct also holds the pointers to the beginning and end of the current packet and overall length,
    to reduce the number of times we have to cast between the 'xdp_md' structs data/data_end ints to void pointers.

    This isn't strictly required, but it is useful to encapsulate this information to clean up the implementation,
    of an XDP program.
*/
struct context
{
    void *data_start;
    void *data_end;
    __u32 length;

    __u32 nh_proto;
    __u32 nh_offset;
};

/*
    The next two definitions 'lpm_v4_key', and 'lpm_v6_key' are used in the layer3 parsers, but from user space
    we utilize 'bpf_lpm_trie_key' due to its capability of being arbitrarilly large. This is discussed in the comments
    of the xdpfw_kern.c source file.

    These are specifically leveraged in the definition of 'BPF_MAP_TYPE_LPM_TRIE' maps, and are critical to support
    matching on ranges of IP addresses i.e. '192.168.0.0/16'. This is done by preforming a longest prefix match (lpm)
    against a trie of values. We won't be going over the algorithm used here in detail in this workshop, but in general
    this allows for matching '192.168.0.1' against the prefix '192.168.0.0/16' but skipping against the prefix '10.0.0.0/8'.
*/

/*
    'lpm_v4_key' represents a IPv4 address range to match against, and is identical to its IPv6 counter part other
    than its address length.
*/
struct lpm_v4_key
{
    __u32 prefixlen;
    __u8 address[4];
};

/*
    'lpm_v6_key' represents a IPv6 address range to match against, and is identical to its IPv4 counter part other
    than its address length.
*/
struct lpm_v6_key
{
    __u32 prefixlen;
    __u8 address[16];
};

/*
    'port_type' here represents the type of the port we wish to drop, either a source or a destination port in this case.
*/
enum port_type
{
    source_port,
    destination_port,
};

/*
    'port_protocol' here represents the protocol of the port we wish to drop, either a tcp or udp port in this case.
*/
enum port_protocol
{
    tcp_port,
    udp_port,
};

/*
    'port_key' is the struct we will be using to match on udp or tcp ports in our firewall. Notice that this structure, could be
    arbitraily complex, and as an example is using an enums as a fields.

    It's important to realize that a BPF map is doing a raw byte hash of the key's value and disregards that actual C type of the
    data. So given a key's byte structure is identical it will match even if those value's types are different. However you need
    to take care that byte boundries are honored, in this case we have to use a '__u32' even though a port is never larger than a
    '__u16' to ensure that the extra padding to fulfill the byte boundry of '12' here is properly handled. This is a rather lowlevel
    concept but the simple explanation is that the struct you are using as a key needs to have a byte size divisable by 4 otherwise the
    compiler will add padding bytes to satisfy that requirement and it may (or may not) throw off matching in the map.
*/
struct port_key
{
    enum port_type type;
    enum port_protocol proto;
    __u32 port;
};

#ifndef XDP_MAX_ACTIONS
#define XDP_MAX_ACTIONS (XDP_REDIRECT + 1)
#endif

#endif /* _COMMON_H */
