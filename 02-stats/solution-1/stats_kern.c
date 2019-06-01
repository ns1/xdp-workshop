// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>

#include "kernel/bpf_helpers.h"

#include "common.h"

struct bpf_map_def SEC("maps") counters = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counters),
    .max_entries = 1,
};

SEC("stats")
int stats_fn(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    __u64 length = data_end - data;

    __u32 counter_idx = 0;
    struct counters *cnt = bpf_map_lookup_elem(&counters, &counter_idx);

    /*
        ---------- SOLUTION ----------

        No matter what map type you are querying, you MUST check the validity of the
        returned value pointer or the verifier will reject the xdp program, with the error:
            invalid mem access 'map_value_or_null'

        This is to keep null pointer exceptions from happening within the XDP program and therefore the kernel.
    */
    if (!cnt)
    {
        return XDP_ABORTED;
    }
    /*
        -------- END SOLUTION --------
    */

    __sync_fetch_and_add(&cnt->packets, 1);
    __sync_fetch_and_add(&cnt->bytes, length);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
