#ifndef _LAYER4_MAPS_H
#define _LAYER4_MAPS_H

#include <linux/bpf.h>

#include "bpf_helpers.h"
#include "structs.h"

struct bpf_map_def SEC("maps") udp_port_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct port_key),
    .value_size = 1,
    .max_entries = PORT_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") tcp_port_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(struct port_key),
    .value_size = 1,
    .max_entries = PORT_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

#endif /* _LAYER4_MAPS_H */
