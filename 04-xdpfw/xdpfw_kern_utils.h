// SPDX-License-Identifier: GPL-2.0

#ifndef _UTILS_H
#define _UTILS_H

#include <linux/bpf.h>

#include "kernel/bpf_endian.h"
#include "kernel/bpf_helpers.h"

#include "workshop/common.h"

#include "common.h"

/*
    'to_ctx' handles taking in the supplied 'xdp_md' structure and converting it to our custom context structure for use throughout the XDP
    program.
*/
static __always_inline struct context to_ctx(struct xdp_md *xdp_ctx)
{
    struct context ctx = {
        .data_start = (void *)(long)xdp_ctx->data,
        .data_end = (void *)(long)xdp_ctx->data_end,
        .nh_proto = 0,
        .nh_offset = 0,
    };
    ctx.length = ctx.data_end - ctx.data_start;

    return ctx;
}

/*
    This is the same BPF map definition we used in the last section, in order to track the counters for each action returned by the XDP program.
*/
struct bpf_map_def SEC("maps") action_counters = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counters),
    .max_entries = XDP_MAX_ACTIONS,
};

/*
    The function 'update_action_stats' handles taking the packet context and desired action, return code of this program, and updates the
    'action_counters' map defined above with the number of packets and bytes processed.

    In the event that the supplied action is not defined, i.e. it doesn't exist in the map, the function short circuits and returns XDP_ABORTED.
*/
static __always_inline __u32 update_action_stats(struct context *ctx, __u32 action)
{
    struct counters *counters = bpf_map_lookup_elem(&action_counters, &action);
    if (!counters)
    {
        return XDP_ABORTED;
    }

    counters->packets += 1;
    counters->bytes += ctx->length;

    return action;
}

#endif /* _UTILS_H */
