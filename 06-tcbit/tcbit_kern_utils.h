// SPDX-License-Identifier: GPL-2.0

#ifndef _TCBIT_KERN_UTILS_H
#define _TCBIT_KERN_UTILS_H

#include <linux/bpf.h>

#include "kernel/bpf_helpers.h"

#include "workshop/common.h"
#include "workshop/kern/action_counters.h"
#include "workshop/kern/bpf_debug.h"

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

#endif // _TCBIT_KERN_UTILS_H
