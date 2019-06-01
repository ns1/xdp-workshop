// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>

#include "kernel/bpf_helpers.h"

#include "common.h"

/*
    This definition represents a BPF map object named 'counters', that is of type
    'BPF_MAP_TYPE_ARRAY'. Because this type is not a PERCPU version it is NOT thread safe.
    Meaning any manipulation of the map itself should be guarded using locking.

    The key pieces of information defined here describe how the map can be interacted with.
        - 'type' is likely the most important piece as it describes the memory layout and functionality of the map.
        - 'key_size' sets the _size_ of the key used to lookup, insert, update, or delete elements.
        - 'value_size' sets the _size_ of the values stored at a given key.
        - 'max_entries' determines the number of keys and therefore values that can be stored in this map.
*/
struct bpf_map_def SEC("maps") counters = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counters),
    .max_entries = 1,
};

SEC("stats")
int stats_fn(struct xdp_md *ctx)
{
    /*
        The xdp_md struct represents the packet and is comprised of two key fields we care about for now:

        struct xdp_md {
            __u32 data;
            __u32 data_end;
            <-- snip -->
        };

        Where 'data' represents the start of the packet data, and `data_end` represents the end of the packet data.

        In order to properly see the size of the packet in question we need to cast the data and data_end fields,
        to void pointers and then do pointer arithmetic to get the resulting difference.
    */
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /*
        Calculate the length of the packet by taking the differnce between end pointer location an the start
        pointer location. This will give you the length of the packet in bytes.
    */
    __u64 length = data_end - data;

    /*
        We need to retrieve a pointer to the actual map element we wish to update
        with the new data.

        Notice how the 'bpf_map_lookup_elem' function takes a pointer to the index
        value being queried, and not the value itself.
    */
    __u32 counter_idx = 0;
    struct counters *cnt = bpf_map_lookup_elem(&counters, &counter_idx);

    /*
        Because we used a 'BPF_MAP_TYPE_ARRAY' map object we need to make sure our
        changes are atomic, so we need to use '__sync_fetch_and_add' or we risk
        multithreading issues.
    */
    __sync_fetch_and_add(&cnt->packets, 1);
    __sync_fetch_and_add(&cnt->bytes, length);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
