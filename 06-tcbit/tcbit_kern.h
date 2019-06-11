#ifndef _COMMON_H
#define _COMMON_H

#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/types.h>
#include <linux/udp.h>

#ifndef XDP_MAX_ACTIONS
#define XDP_MAX_ACTIONS (XDP_REDIRECT + 1)
#endif

#ifndef XDP_CONTINUE
#define XDP_CONTINUE XDP_MAX_ACTIONS
#endif

/* Pulled from $(LINUX)/include/linux/if_vlan.h#L38 */
struct vlan_hdr
{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

/*
    'context' here is a bit more complex this time around since we need to keep track of the various header objects so that 
    when we go to retransmit this packet we can properly update the various addresses and checksums to ensure that the response
    goes to the correct client and isn't dropped by networking hardware on the way back.
*/
struct context
{
    void *data_start;
    void *data_end;
    __u32 length;

    __u32 nh_proto;
    __u32 nh_offset;

    struct ethhdr *eth;
    struct iphdr *v4;
    struct ipv6hdr *v6;
    struct udphdr *udp;
    struct dnshdr *dns;
};

/*
    'dns_flag_bits' is just a bitfield struct to handle updating the various flags and options in a dns packet header.
*/
struct dns_flag_bits
{
    __u16 rd : 1,
        tc : 1,
        aa : 1,
        opcode : 4,
        qr : 1,
        rcode : 4,
        zero : 3,
        ra : 1;
};

/*
    We are using a union as our primary dns_flags object so that we can easily track the initial and then changed value to update checksum based on our changes
    to the header fields.
*/
union dns_flags {
    __u16 data;
    struct dns_flag_bits bits;
};

/*
    This is just a truncated dnshdr struct that only concerns itself with the beginning id and flags of the dns packet.
*/
struct dnshdr
{
    __u16 id;
    union dns_flags flags;
};

#endif /* _COMMON_H */
