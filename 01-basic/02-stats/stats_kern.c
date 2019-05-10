/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include "bpf_helpers.h"
#include "common.h"

struct bpf_map_def SEC("maps") counter_map = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counters),
    .max_entries = 1,
};

static __always_inline __u8 update_counters(struct xdp_md *ctx)
{
    /* The xdp_md represents the packet and is comprised of three fields:
   *
   * struct xdp_md {
   *     __u32 data;
   *     __u32 data_end;
   *     __u32 data_meta;
   *     <-- snip -->
   * };
   *
   * In order to properly see the size of the packet in question we need to cast
   * the data and data_end fields, to void pointers and then do pointer
   * arithmetic to get the resulting difference.
   */
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Calculate packet length */
    __u64 length = data_end - data;

    /* We need to retrieve a pointer to the actual map element we wish to update
   * with the new data.
   *
   * Notice how the 'bpf_map_lookup_elem' function takes a pointer to the index
   * value being queried, and not the value itself.
   */
    __u32 counter_idx = 0;
    struct counters *counters = bpf_map_lookup_elem(&counter_map, &counter_idx);

    /* No matter what you are querying, you MUST check the validity of the
   * returned value or the verifier will reject the xdp program.
   *
   * This is to keep null pointer exceptions from happening within the XDP program.
   */
    if (!counters)
    {
        return 1;
    }

    /* Because we used a 'BPF_MAP_TYPE_ARRAY' map object we need to make sure our
   * changes are atomic, so we need to use '__sync_fetch_and_add' or we risk
   * multithreading issues.
   *
   * We will be removing this requirement by moving to a
   * BPF_MAP_TYPE_PERCPU_ARRAY which doesn't have this limitation.
   */
    __sync_fetch_and_add(&counters->packets, 1);
    __sync_fetch_and_add(&counters->bytes, length);

    return 0;
}

SEC("stats")
int stats_fn(struct xdp_md *ctx)
{
    if (update_counters(ctx) != 0)
    {
        return XDP_ABORTED;
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
