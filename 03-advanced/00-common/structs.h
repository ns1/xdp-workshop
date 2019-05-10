#ifndef _STRUCTS_H
#define _STRUCTS_H

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

/* The counters struct bellow represents the number of packets and bytes a given
 * XDP program has encountered.
 *
 * Notice that there is no distinction between RX and TX since XDP programs only
 * see RX and have no ability to interact with, packets transmitted from the
 * host.
 */
struct counters
{
    __u64 packets;
    __u64 bytes;
};

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
};

struct dnshdr
{
    __u16 id;
#if __BYTE_ORDER == __LITTLE_ENDIAN // Reversed because we are parsing
    __u16 qr : 1;
    __u16 opcode : 4;
    __u16 aa : 1;
    __u16 tc : 1;
    __u16 rd : 1;
    __u16 ra : 1;
    __u16 zero : 3;
    __u16 rcode : 4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    __u16 rd : 1;
    __u16 tc : 1;
    __u16 aa : 1;
    __u16 opcode : 4;
    __u16 qr : 1;
    __u16 rcode : 4;
    __u16 zero : 3;
    __u16 ra : 1;
#else
#error "Adjust your <bits/endian.h> defines"
#endif
    __u16 qdcount;
    __u16 ancount;
    __u16 nscount;
    __u16 adcount;
};

#endif /* _STRUCTS_H */
