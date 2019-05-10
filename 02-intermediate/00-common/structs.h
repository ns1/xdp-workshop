#ifndef _STRUCTS_H
#define _STRUCTS_H

#include <linux/types.h>

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

static const int v4_lpm_trie_key_size =
    sizeof(struct bpf_lpm_trie_key) + sizeof(__u32);
static const int v6_lpm_trie_key_size =
    sizeof(struct bpf_lpm_trie_key) + sizeof(__u32) * 4;

struct lpm_v4_key
{
    struct bpf_lpm_trie_key lpm;
    __u8 padding[4];
};

struct lpm_v6_key
{
    struct bpf_lpm_trie_key lpm;
    __u8 padding[16];
};

static const __u16 SOURCE_PORT = 0;
static const __u16 DEST_PORT = 1;

struct port_key
{
    __u16 direction;
    __u16 port;
};

#ifndef XDP_MAX_ACTIONS
#define XDP_MAX_ACTIONS (XDP_REDIRECT + 1)
#endif

#ifndef MAC_BLACKLIST_MAX_ENTRIES
#define MAC_BLACKLIST_MAX_ENTRIES 4096
#endif

#ifndef V4_BLACKLIST_MAX_ENTRIES
#define V4_BLACKLIST_MAX_ENTRIES 10000
#endif

#ifndef V6_BLACKLIST_MAX_ENTRIES
#define V6_BLACKLIST_MAX_ENTRIES 10000
#endif

#ifndef PORT_BLACKLIST_MAX_ENTRIES
#define PORT_BLACKLIST_MAX_ENTRIES (65535 * 2) /* src + dest */
#endif

#endif /* _STRUCTS_H */
