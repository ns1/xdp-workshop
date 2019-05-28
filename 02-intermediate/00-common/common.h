#ifndef _COMMON_H
#define _COMMON_H

#include <linux/types.h>

struct context
{
    void *data_start;
    void *data_end;
    __u32 length;

    __u32 nh_proto;
    __u32 nh_offset;
};

/* Pulled from $(LINUX)/include/linux/if_vlan.h#L38 */
struct vlan_hdr
{
    __be16 h_vlan_TCI;
    __be16 h_vlan_encapsulated_proto;
};

static const int v4_lpm_trie_key_size = sizeof(struct bpf_lpm_trie_key) + sizeof(__u32);
static const int v6_lpm_trie_key_size = sizeof(struct bpf_lpm_trie_key) + sizeof(__u32) * 4;

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

enum port_type
{
    source_port,
    destination_port,
};

struct port_key
{
    enum port_type type;
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

#endif /* _COMMON_H */
