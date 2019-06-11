// SPDX-License-Identifier: GPL-2.0

#ifndef _ACTION_COUNTERS_H
#define _ACTION_COUNTERS_H

#include <linux/bpf.h>
#include <linux/types.h>

#include "kernel/bpf_helpers.h"

#include "workshop/common.h"

#ifndef XDP_MAX_ACTIONS
#define XDP_MAX_ACTIONS (XDP_REDIRECT + 1)
#endif

/*
    This is our tried and true action_counters and is used in the same was as the previous exercies.
*/
struct bpf_map_def SEC("maps") action_counters = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counters),
    .max_entries = XDP_MAX_ACTIONS,
};

/*
    This is the same 'update_action_stats' as the previous section but just modified to work without a context
    struct and just has then packet length passed in directly.
*/
static __always_inline __u32 update_action_stats(__u16 length, __u32 action)
{
    struct counters *counters = (struct counters *)bpf_map_lookup_elem(&action_counters, &action);
    if (!counters)
    {
        return XDP_ABORTED;
    }

    counters->packets += 1;
    counters->bytes += length;

    return action;
}

#endif // _ACTION_COUNTERS_H
