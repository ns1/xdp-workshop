#ifndef _UTILS_H
#define _UTILS_H

#include <linux/bpf.h>

#include "bpf_helpers.h"
#include "structs.h"

struct bpf_map_def SEC("maps") action_counters = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counters),
    .max_entries = XDP_MAX_ACTIONS,
};

static __always_inline void *get_data(struct xdp_md *ctx)
{
    return (void *)(long)ctx->data;
}

static __always_inline void *get_data_end(struct xdp_md *ctx)
{
    return (void *)(long)ctx->data_end;
}

static __always_inline __u64 get_length(struct xdp_md *ctx)
{
    void *data_end = get_data_end(ctx);
    void *data = get_data(ctx);

    return data_end - data;
}

static __always_inline __u32 update_action_stats(struct xdp_md *ctx, __u32 action)
{
    struct counters *counters;
    counters = (struct counters *)bpf_map_lookup_elem(&action_counters, &action);
    if (!counters)
    {
        return XDP_ABORTED;
    }

    counters->packets += 1;
    counters->bytes += get_length(ctx);

    return action;
}

#endif /* _UTILS_H */
