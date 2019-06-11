// SPDX-License-Identifier: GPL-2.0

#include "sampler_kern.h"

/*
    'sample_rate' here represents the user specified rate at which to capture packets and pass them off to user space 
    for inspection.

    The value here is the number of packets to skip, i.e. a rate of 100 means capture 1 packet every 100 packets observed.
    We are using a single entry to control the entire program as well as a non PERCPU variant because we don't ever update 
    this value from the XDP program itself.
*/
struct bpf_map_def SEC("maps") sample_rate = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

/*
    'packet_count' here is an internal only map for each CPU processing packets for this XDP program to keep track of the total
    number of packets observed for the rate calculation.
*/
struct bpf_map_def SEC("maps") packet_count = {
    .type = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u32),
    .max_entries = 1,
};

/*
    'samples' here is the star of this program and is how we will be exposing the observed packet data with userspace.
    This paricular map is using a new type here 'BPF_MAP_TYPE_PERF_EVENT_ARRAY', and it has some interesting qualtiies that
    make it ideal for this usecase.

    First and foremost lets take a look at the general definition of this map, we are using a simple '__u32' key, which in reality
    will be the CPU id of the executing process. The value is slightly more interesting, and its definition is in 'sampler_kern.h' the
    interesting bit is that it doesn't have a 'data' field or really anything that would actually allow us to pass off the packet data,
    more on this point later. The max entries here is an arbitrary upper bound on the maximum number of CPU's we expect to ever run this
    XDP program.

    So lets dig in the point that the value specified in this MAP definition doesn't actually allow us to pass off the packet data.
    The way this works is explained in detail in the code bellow, but it comes down to how we will be leveraging this particular map,
    most importantly we will not be using the 'bpf_map_*' helpers we have become accustomed to. We will be using the helper 
    'bpf_perf_event_output', which allows us to pass in the 'struct xdp_md' we are supplied at the entry point.
*/
struct bpf_map_def SEC("maps") samples = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct perf_metadata),
    .max_entries = MAX_CPUS,
};

SEC("sampler")
int sampler_fn(struct xdp_md *xdp_ctx)
{
    /*
        Setup some storage variables and specify our general key for accessing the 'sample_rate' and 'packet_count' maps, since
        they both only have a single entry.
    */
    __u32 action = XDP_PASS;
    __u32 key = 0;

    /*
        Lets grab the length of this packet for use down the line.
    */
    __u16 length = (void *)(long)xdp_ctx->data_end - (void *)(long)xdp_ctx->data;

    /*
        Grab the user supplied rate if it exists, in this particular case if it isn't specified by the user it will automatically
        defualt to '0'.
    */
    __u32 *current_sample_rate = bpf_map_lookup_elem(&sample_rate, &key);
    if (!current_sample_rate)
    {
        action = XDP_ABORTED;
        goto ret;
    }

    /*
        Grab the current packet count for this particular CPU and increment it by one, and since this paricular MAP is a 'PERCPU'
        variant we can bypass any locking.
    */
    __u32 *current_packet_count = bpf_map_lookup_elem(&packet_count, &key);
    if (!current_packet_count)
    {
        action = XDP_ABORTED;
        goto ret;
    }

    *current_packet_count += 1;

    /*
        Just run some numbers and sample the packt if the sampler rate either hasn't be defined and is '0' of if the modulo of the current
        packet count and the configured sample rate is equal to 0.
    */
    if (*current_sample_rate == 0 || *current_packet_count % *current_sample_rate == 0)
    {
        /*
            We will be forcing the call to 'bpf_perf_event_output' to be CPU aware and this is actually
            how the 'key' from the 'samples' map is going to be set.
        */
        __u64 flags = BPF_F_CURRENT_CPU;

        /*
            We generate a simple metadata object for this sampled packet. Note that the cookie in this case is completely arbitrary, and
            could theoretically be any valid '__u16' value. It is used to ensure that in user space we operating on the right data.
        */
        struct perf_metadata metadata = {
            .cookie = 0xcafe,
            .length = length,
        };

        /*
            Here is where the magic happens and is how we specify how much of the packets actual data we want to pass on up to the user space
            application listening for samples.

            The bottom 32 bits of the flags we pass into 'bpf_perf_event_output' controls how the data is handled. The top 32 bits of the flags 
            value is used to determine how many bytes we want to pass off from the ctx object. in this case we take the minimum of the length of
            the packet or the MAX_SAMPLE_SIZE which in this case is 65535.
        */
        __u16 sample_size = length > MAX_SAMPLE_SIZE ? MAX_SAMPLE_SIZE : length;

        /*
            Store the sample size for this packet in the top 32 bits of the flags value.
        */
        flags |= (__u64)sample_size << 32;

        /*
            Lets actually hand off the context, to the 'samples' map and use the specified flags and metadata object in conjunction to allow userspace
            to properly identify the perf event, and so we pass as much of the packet data as we can for analysis.
        */
        int ret = bpf_perf_event_output(xdp_ctx, &samples, flags, &metadata, sizeof(metadata));
        if (ret)
        {
            /*
                If we failed to write the event let someone know via the trace_pipe we used earlier.
            */
            bpf_debug("failed to write sampled packet data err(%d)\n", ret);
        }
    }

ret:
    return update_action_stats(length, action);
}

char _license[] SEC("license") = "GPL";
