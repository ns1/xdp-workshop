#ifndef _LAYER2_MAPS_H
#define _LAYER2_MAPS_H

#include <linux/bpf.h>
#include <linux/if_ether.h>

#include "bpf_helpers.h"
#include "structs.h"

struct bpf_map_def SEC("maps") mac_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = ETH_ALEN,
    .value_size = 1,
    .max_entries = MAC_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

#endif /* _LAYER2_MAPS_H */
