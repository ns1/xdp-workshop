/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include "bpf_helpers.h"
#include "common.h"

struct bpf_map_def SEC("maps") action = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(long),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") action_counters = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counters),
    .max_entries = XDP_MAX_ACTIONS,
};

static __always_inline __u32 update_action_stats(struct xdp_md *ctx, __u32 action)
{
    /* The xdp_md represents the packet and is comprised of three fields:
     *
     * struct xdp_md {
     *     __u32 data;
     *     __u32 data_end;
     *     __u32 data_meta;
     * };
     *
     * In order to properly see the size of the packet in question we need to cast the data and data_end fields,
     * to void pointers and then do pointer arithmetic to get the resulting difference.
     */
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    /* Calculate packet length */
    __u64 length = data_end - data;

    /* We need to retrieve a pointer to the actual map element we wish to update with the new data.
     *
     * Notice how the 'bpf_map_lookup_elem' function takes a pointer to the index value being queried,
     * and not the value itself.
     */
    struct counters *counters = bpf_map_lookup_elem(&action_counters, &action);

    /* No matter what you are querying, you MUST check the validity of the returned value or the verifier will reject the xdp program.
     *
     * This is to keep null pointer exceptions from happening in the XDP program.
     */
    if (!counters)
    {
        return XDP_ABORTED;
    }

    /* Because we used a 'BPF_MAP_TYPE_PERCPU_ARRAY' map object we do NOT need to make sure our changes are atomic. */
    counters->packets += 1;
    counters->bytes += length;

    return action;
}

static __always_inline __u32 get_action()
{
    __u32 action_idx = 0;
    __u32 *elem = bpf_map_lookup_elem(&action, &action_idx);
    if (!elem)
    {
        return XDP_ABORTED;
    }

    return *elem;
}

SEC("stats")
int stats_fn(struct xdp_md *ctx)
{
    __u32 action = get_action();

    return update_action_stats(ctx, action);
}

char _license[] SEC("license") = "GPL";
