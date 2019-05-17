// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>

#include "bpf_helpers.h"
#include "common.h"

struct bpf_map_def SEC("maps") counters = {
    /*
        ---------- SOLUTION ----------

        The key piece that we are changing here is to use a BPF_MAP_TYPE_PERCPU_ARRAY,
        which allocates a entry for every CPU. Notice how even though we have 'max_entries'
        limited to '1' still we will actually end up that value multiplied by the number of CPU's
        the system running this program has.

        The above is important to keep in mind when handling large maps as memory can become an issue
        quickly.
    */
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    /*
        -------- END SOLUTION --------
    */
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

    if (!cnt)
    {
        return XDP_ABORTED;
    }

    /*
        ---------- SOLUTION ----------

        Because we updated the map definition to a PERCPU array we no longer need the calls to,
        '__sync_fetch_and_add' because each instance of this XDP program gets its own entry to work with
        removing the need to worry about multi-threading.

        The userspace application handles combining the PERCPU values.
    */
    cnt->packets += 1;
    cnt->bytes += length;
    /*
        -------- END SOLUTION --------
    */

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
