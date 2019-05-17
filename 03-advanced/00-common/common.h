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

#ifndef MAX_VLAN_DEPTH
#define MAX_VLAN_DEPTH 10
#endif

/* Pulled from $(LINUX)/include/linux/if_vlan.h#L38 */
struct vlan_hdr
{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

struct metadata
{
    __u32 nh_offset;
    __u32 nh_proto;

    struct ethhdr *eth;
    struct iphdr *v4;
    struct ipv6hdr *v6;
    struct udphdr *udp;
    struct dnshdr *dns;
    struct dnshdr_compare *dns_compare;
};

struct dnshdr_compare
{
    __u16 id;
    __u16 flags;
};

struct dnshdr
{
    __u16 id;
    __u16 rd : 1,
        tc : 1,
        aa : 1,
        opcode : 4,
        qr : 1,
        rcode : 4,
        zero : 3,
        ra : 1;
};

#endif /* _COMMON_H */
