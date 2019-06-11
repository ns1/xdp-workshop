# sampler
This exercise dives into how we can leverage the perf event subsystem of the kernel to sample full packet data from an XDP program into userspace for analysis and dissection offline. This specifically leverages the helper function `bpf_perf_event_output` to sample packet data, and the user space application is leveraging a combination of polling and `bpf_perf_event_read_simple` to actually view the sampled data.

## `bpf_perf_event_output`
So this function is a BPF helper function the is specifically used in kernel space applications to pass around data.

The signature is as follows:

```
static int bpf_perf_event_output(void *ctx, void *map, unsigned long long flags, void *data, int size)
```

The above function may not make sense at first and is a bit unintuitive at first glance so lets break it down. 

#### `void *ctx`
First off the `void *ctx` in the context of an XDP program is the `struct xdp_md` pointer supplied to the XDP program as the entry point. So in the case of the XDP program in use in this exercise it would be the value `xdp_ctx` passed into the function `sampler_fn`.

#### `void *map`
The `void *map` is a BPF map of type `BPF_MAP_TYPE_PERF_EVENT_ARRAY`, which should have a metadata object as the value and _not_ a value of the sample size you want to capture. Which might seem like a strange situation so lets take a look at the definition in some detail:

```
struct bpf_map_def SEC("maps") samples = {
    .type = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct perf_metadata),
    .max_entries = MAX_CPUS,
};
```

So clearly the type is set to the `BPF_MAP_TYPE_PERF_EVENT_ARRAY` but we see a key size of `__u32` which in this particular case and exercise will be representitive of the CPU id that is executing the XDP program more on that in just a bit. and the value size in this case is the size of the `struct perf_metadata` which is a custom struct reproduced bellow:

```
struct perf_metadata
{
    __u16 cookie;
    __u16 length;
} __packed;
```

Notice how the struct has no mention of the actual packet data, and that all it contains are two `__u16` fields denoting a cookie and length, again more on that in a bit.

#### `unsigned long long flags`
So this is where things get interesting, this value is 64 bits and because of that can actually store quite a bit of information. The top 32 bits of the value store the length of data from the supplied `ctx` that you want to capture into the event you are outputing. The bottom 32 bits of the value denote how you want the event handled by the kernel in our case we are setting it to be a CPU based handling where each CPU has its own perf event ring available. The code bellow shows this in action:

```
    __u64 flags = BPF_F_CURRENT_CPU;
    <-- snip -->
    __u16 sample_size = length > MAX_SAMPLE_SIZE ? MAX_SAMPLE_SIZE : length;
    
    flags |= (__u64)sample_size << 32;
```

So in the above we set the flags to `BPF_F_CURRENT_CPU` which is what sets the key for where to store the new event and which file descriptor to trigger a wakup event on in our MAP object we supplied to the function. And then we `|=` in the sample size shifted by 32 bits to tell the function how much of the data from `ctx` we want to capture.

#### `void *data, int size`
The last two arguments are pretty straight forward and amount to the `struct perf_metadata` object and its size in bytes. However its important to note what the fields represent and why they are needed. Firstly the `cookie` field in our struct is used to denote a valid perf event and that from userspace we are operating on the correct unmangled data from the call to `bpf_perf_event_output`. The `length` field is used to tell the user space application what the sample length is in bytes so that when it parses the data payload it knows how much data to read in.

## `bpf_perf_event_read_simple`
So this function is the user space sibling of the calls to `bpf_perf_event_output` and handles reading event data from a BPF based kernel application. This is used in combination with polling and some syscalls to setup perf event file desceriptors bound to our BPF map.

This is a bit lengthy in terms of the amount of code but the process is as such:
- Create a file descriptor enabled for receiving event updates.
- Create a MMAP region which is associated with the file descriptor created in the previous calls.
- Then poll for events on the file descriptor
- Once an event is received pass the mmap region associated with it to the call `bpf_perf_event_read_simple`

This is best explained in code, so please take a look at `sampler_user.c` to see the full call stack to set up the system and then print out the data seen.
