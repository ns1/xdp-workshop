#ifndef _MAPS_H
#define _MAPS_H

#include <linux/bpf.h>

#include "bpf_helpers.h"
#include "structs.h"

struct bpf_map_def SEC("maps") progs = {
    .type = BPF_MAP_TYPE_PROG_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 6,
};

#endif /* _MAPS_H */
