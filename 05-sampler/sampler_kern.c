// SPDX-License-Identifier: GPL-2.0

#include "sampler_kern.h"

struct bpf_map_def SEC("maps") sample_rate = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") packet_count = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

struct bpf_map_def SEC("maps") samples = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct perf_metadata),
    .max_entries = MAX_CPUS,
};

SEC("sampler")
int sampler_fn(struct xdp_md *xdp_ctx)
{
    __u32 action = XDP_PASS;
    __u32 key = 0;

    struct context ctx = to_ctx(xdp_ctx);

    __u32 *current_sample_rate = bpf_map_lookup_elem(&sample_rate, &key);
    if (!current_sample_rate)
    {
        action = XDP_ABORTED;
        goto ret;
    }

    __u32 *current_packet_count = bpf_map_lookup_elem(&packet_count, &key);
    if (!current_packet_count)
    {
        action = XDP_ABORTED;
        goto ret;
    }

    *current_packet_count += 1;

    if (*current_sample_rate == 0 || *current_packet_count % *current_sample_rate == 0)
    {
        __u64 flags = BPF_F_CURRENT_CPU;

        struct perf_metadata metadata = {
            .cookie = 0xcafe,
            .length = ctx.length,
        };

        __u16 sample_size = ctx.length > MAX_SAMPLE_SIZE ? MAX_SAMPLE_SIZE : ctx.length;
        flags |= (__u64)sample_size << 32;

        int ret = bpf_perf_event_output(xdp_ctx, &samples, flags, &metadata, sizeof(metadata));
        if (ret)
        {
            bpf_debug("failed to write sampled packet data err(%d)\n", ret);
        }
    }

ret:
    return update_action_stats(&ctx, action);
}

char _license[] SEC("license") = "GPL";
