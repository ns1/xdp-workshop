/* SPDX-License-Identifier: GPL-2.0 */

#include <linux/bpf.h>

#include "bpf_helpers.h"
#include "structs.h"

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
    .max_entries = 5,
};

static __always_inline __u32 update_action_stats(struct xdp_md *ctx, __u32 action)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u64 length = data_end - data;

    struct counters *counters = bpf_map_lookup_elem(&action_counters, &action);

    if (!counters)
    {
        return XDP_ABORTED;
    }

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
