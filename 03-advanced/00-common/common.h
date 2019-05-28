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

union dns_flags {
    __u16 data;
    struct dns_flag_bits bits;
};

struct dnshdr
{
    __u16 id;
    union dns_flags flags;
};

#endif /* _COMMON_H */
