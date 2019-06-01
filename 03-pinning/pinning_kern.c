// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>

#include "kernel/bpf_helpers.h"

#include "workshop/common.h"

/*
    This definition is similar to the 'counters' definition in the last section.

    The key difference here is we are going to be updating this map from user space in this section.
*/
struct bpf_map_def SEC("maps") action = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(long),
    .max_entries = 1,
};

/*
    This definition is again similar to the 'counters' definition updated to a PERCPU array in the last section.

    The key difference here is we now have 5 elements which represent the various return codes an XDP program can
    return. This will be used throughout the rest of the workshop as a means of debugging and tracking what each
    program is deciding to do and how often.
*/
struct bpf_map_def SEC("maps") action_counters = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counters),
    .max_entries = 5,
};

/*
    This is the first time we have introduced separate function calls, and there are a few things to keep in mind about them.
    They generally must be inlined into the calling function meaning they need the attribute defined here '__always_inline'. However,
    in more recent iterations of XDP this requirement has been relaxed and you can call non-inlined functions. That being said you must
    keep in mind that it introduces complexities that should be addressed and that we won't be covering today.
*/

/*
    The function 'update_action_stats' handles taking the packet context and desired action, return code of this program, and updates the
    'action_counters' map defined above with the number of packets and bytes processed.

    In the event that the supplied action is not defined, i.e. it doesn't exist in the map, the function short circuits and returns XDP_ABORTED.
*/
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

/*
    The function 'get_action' handles retrieving the defined return code for the xdp program 'stats'. If it is not defined yet by the user space
    control program, XDP_ABORTED is returned.
*/
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
    /*
        Grab the user defined action for this program to return.
    */
    __u32 action = get_action();

    /*
        Update the stats on the user defined action and return the action to the kernel.
    */
    return update_action_stats(ctx, action);
}

char _license[] SEC("license") = "GPL";
