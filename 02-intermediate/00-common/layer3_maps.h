#ifndef _LAYER3_MAPS_H
#define _LAYER3_MAPS_H

#include <linux/bpf.h>

#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") v4_blacklist = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = v4_lpm_trie_key_size,
    .value_size = 1,
    .max_entries = V4_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

struct bpf_map_def SEC("maps") v6_blacklist = {
    .type = BPF_MAP_TYPE_LPM_TRIE,
    .key_size = v6_lpm_trie_key_size,
    .value_size = 1,
    .max_entries = V6_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};

#endif /* _LAYER3_MAPS_H */
