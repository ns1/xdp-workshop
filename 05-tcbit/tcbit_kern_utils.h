// SPDX-License-Identifier: GPL-2.0

#ifndef _TCBIT_KERN_UTILS_H
#define _TCBIT_KERN_UTILS_H

#include <linux/bpf.h>

#include "kernel/bpf_helpers.h"

#include "workshop/common.h"

#define bpf_debug(fmt, ...)                                        \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

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

struct bpf_map_def SEC("maps") action_counters = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counters),
    .max_entries = XDP_MAX_ACTIONS,
};

static __always_inline __u32 update_action_stats(struct context *ctx, __u32 action)
{
    struct counters *counters = (struct counters *)bpf_map_lookup_elem(&action_counters, &action);
    if (!counters)
    {
        return XDP_ABORTED;
    }

    counters->packets += 1;
    counters->bytes += ctx->length;

    return action;
}

#endif // _TCBIT_KERN_UTILS_H
