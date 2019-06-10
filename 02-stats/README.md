# Stats
In this exercise we are going to be diving into BPF maps and how to debug XDP verifier failures.

## XDP Verifier
The XDP verifier is a watch dog of sorts that is run over **every** XDP program that is loaded into the kernel. It's primary purpose is to ensure that the loaded programs are safe and fit in within the specifications of XDP.

There are a few key things that the verifier ensures:
- The XDP program is within the maximum 4096 instructions.
- That there are no out of bounds errors, i.e. accessing memory that is not within the packet being parsed.
- There are no jumps backwards in the program.
- There are no possibilites for NULL pointer exceptions.

The rational for the stringent set of rules for XDP programs is that every XDP program operates inside the kernel, and in the case of XDP on every packet that is received on a given network interface. Imagine if a XDP program was rather long what would happen to network performance, or if there was a NULL pointer exception deep within the kernel.

Lets take a look at what happens when the XDP verfier fails and rejects a program. Go ahead and call `make` in this directory and then try to attach the resulting `stats_kern.o` to the loopback interface much like we did in the last exercise:

```
$ sudo ip link set dev lo xdp obj stats_kern.o sec stats
Prog section 'stats' rejected: Permission denied (13)!
 - Type:         6
 - Instructions: 15 (0 over limit)
 - License:      GPL

Verifier analysis:

0: (61) r6 = *(u32 *)(r1 +0)
1: (61) r7 = *(u32 *)(r1 +4)
2: (b7) r1 = 0
3: (63) *(u32 *)(r10 -4) = r1
4: (bf) r2 = r10
5: (07) r2 += -4
6: (18) r1 = 0xffff9c97f6e41a00
8: (85) call bpf_map_lookup_elem#1
9: (b7) r1 = 1
10: (db) lock *(u64 *)(r0 +0) += r1
R0 invalid mem access 'map_value_or_null'

Error fetching program/map!
```

So that didn't go as expected, but lets take a close look at what we got returned here. The first section:

```
Prog section 'stats' rejected: Permission denied (13)!
 - Type:         6
 - Instructions: 15 (0 over limit)
 - License:      GPL
```

This is metadata about our XDP program, and tells us the type `6` which represents an XDP program. The number of instructions in our program which is `15` well bellow the totall allowed of `4096`, and finally the license of the program.

The second section is the actual verifiers analysis of our program and gives us the clue as to what is wrong:

```
Verifier analysis:

0: (61) r6 = *(u32 *)(r1 +0)
1: (61) r7 = *(u32 *)(r1 +4)
2: (b7) r1 = 0
3: (63) *(u32 *)(r10 -4) = r1
4: (bf) r2 = r10
5: (07) r2 += -4
6: (18) r1 = 0xffff9c97f6e41a00
8: (85) call bpf_map_lookup_elem#1
9: (b7) r1 = 1
10: (db) lock *(u64 *)(r0 +0) += r1
R0 invalid mem access 'map_value_or_null'
```

The last line in this out put is telling us we have an invalid mem access but what does that mean? and where is the actuall invalid memory access happening in our code?

Well the answer the to first question is directly related to the XDP verifier attempting to ensure there are no chances for a NULL pointer exception within our code. The `map_value_or_null` statement points us further in the right direction that this has something to do with a BPF map value. However we are still left with _where_ in the program we had this issue. Well the numbers on the left hand side of the above output are actually instruction indexes, which can be used in conjunction with a new tool `llvm-objdump` to determine where in the C code of `stats_kern.c` we have our error.

Lets take a look at what we get when we run the following:

```
$ llvm-objdump -S stats_kern.o

stats_kern.o:   file format ELF64-BPF

Disassembly of section stats:
0000000000000000 stats_fn:
; {
       0:       61 16 00 00 00 00 00 00         r6 = *(u32 *)(r1 + 0)
; void *data_end = (void *)(long)ctx->data_end;
       1:       61 17 04 00 00 00 00 00         r7 = *(u32 *)(r1 + 4)
       2:       b7 01 00 00 00 00 00 00         r1 = 0
; __u32 counter_idx = 0;
       3:       63 1a fc ff 00 00 00 00         *(u32 *)(r10 - 4) = r1
       4:       bf a2 00 00 00 00 00 00         r2 = r10
; int stats_fn(struct xdp_md *ctx)
       5:       07 02 00 00 fc ff ff ff         r2 += -4
; struct counters *cnt = bpf_map_lookup_elem(&counters, &counter_idx);
       6:       18 01 00 00 00 00 00 00 00 00 00 00 00 00 00 00         r1 = 0 ll
       8:       85 00 00 00 01 00 00 00         call 1
       9:       b7 01 00 00 01 00 00 00         r1 = 1
; __sync_fetch_and_add(&cnt->packets, 1);
      10:       db 10 00 00 00 00 00 00         lock *(u64 *)(r0 + 0) += r1
; __u64 length = data_end - data;
      11:       1f 67 00 00 00 00 00 00         r7 -= r6
; __sync_fetch_and_add(&cnt->bytes, length);
      12:       db 70 08 00 00 00 00 00         lock *(u64 *)(r0 + 8) += r7
; return XDP_PASS;
      13:       b7 00 00 00 02 00 00 00         r0 = 2
      14:       95 00 00 00 00 00 00 00         exit
```

So that might look like gibberish at first but if you compare the above output with the `stats_kern.c` file you will noice each of the lines starting with `;` match up with one of the lines from the `stats_fn` function. Further more we also have the instructions for each of those lines actually being passed to kernel for execution.

Lets take a look at instruction `10` which if you look back a bit is where the verifier failed on our program. That particular function `__sync_fetch_and_add(&cnt->packets, 1)` is the one associated with instruction `10` and it has to do with the value `cnt` returned from the call `bpf_map_lookup_elem`.

So what did we learn from the above? We have a broken XDP program that we need to fix, and we know that the problem is a `map_value_or_null` error from the verifier. The error happens after grabbing a value from the BPF map `counters` using `bpf_map_lookup_elem`, and specifically occurs when we go to increment one of the values fields by one. What do we need to do to fix this?

> Hint: if you are stuck take a look at `solution-1/stats-kern.c`

Once you have a solution go ahead and try to rebuild and attach the program to the loopback interface:

```
$ make
clang -S \
    -target bpf \
    -D __BPF_TRACING__ \
     "-I../../../common/headers/" "-I../../../libbpf/src/root/usr/include/" "-I/usr/include/x86_64-linux-gnu" \
    -Wall \
        -Wno-compare-distinct-pointer-types \
    -O2 -emit-llvm -c -g -o stats_kern.ll stats_kern.c
llc -march=bpf -filetype=obj -o stats_kern.o stats_kern.ll
cc \
         "-I../../../common/headers/" "-I../../../libbpf/src/root/usr/include/" "-I/usr/include/x86_64-linux-gnu" \
        -L../../../libbpf/src \
        -Wall \
        -Wno-unused-variable \
        -O2 -g -o stats_user stats_user.c \
        -l:libbpf.a -lbpf -lelf

$ sudo ip link set dev lo xdp obj stats_kern.o sec stats
```

You should no longer see any verifier output and should have successfully attached the XDP program to the loopback!

## BPF Maps
Now that we have a fix for our program lets take a look at the second part of this exercise which is interacting with and manipulating BPF maps loaded by our program. At the top of the `stats_kern.c` file you should see a BPF map definition:

```
/*
    This definition represents a BPF map object named 'counters', that is of type
    'BPF_MAP_TYPE_ARRAY'. Because this type is not a PERCPU version it is NOT thread safe.
    Meaning any manipulation of the map itself should be guarded using locking.

    The key pieces of information defined here describe how the map can be interacted with.
        - 'type' is likely the most important piece as it describes the memory layout and functionality of the map.
        - 'key_size' sets the _size_ of the key used to lookup, insert, update, or delete elements.
        - 'value_size' sets the _size_ of the values stored at a given key.
        - 'max_entries' determines the number of keys and therefore values that can be stored in this map.
*/
struct bpf_map_def SEC("maps") counters = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(struct counters),
    .max_entries = 1,
};
```

This BPF map is an array of one element using `__u32` keys with `struct counters` values. Take a look at the `common.h` file for the definition of this struct. The program itself is accessing this MAP and incrementing the fields of the stored value by the number of packets and bytes processed by the program.

In order to view this data we have two options we can use `libbpf` to interrogate the file programatically which is what the file `stats_user.c` is doing, or we can use a tool called `bpftool` to take a look at this map in action.

### `bpftool`
Lets start with `bpftool` so that we can both take a peak at the map itself and the values it contains as well as pin it to the file system so that `stats_user` can interact with it from user space.

First and foremost please ensure your corrected `stats_kern.o` is attached to the loop back interface using `iproute2`. Once done go ahead and run this to verify:

```
$ sudo bpftool prog list
3: cgroup_skb  tag 7be49e3934a125ba  gpl
        loaded_at 2019-05-16T14:20:22+0000  uid 0
        xlated 296B  jited 229B  memlock 4096B  map_ids 2,3
4: cgroup_skb  tag 2a142ef67aaad174  gpl
        loaded_at 2019-05-16T14:20:22+0000  uid 0
        xlated 296B  jited 229B  memlock 4096B  map_ids 2,3
5: cgroup_skb  tag 7be49e3934a125ba  gpl
        loaded_at 2019-05-16T14:20:23+0000  uid 0
        xlated 296B  jited 229B  memlock 4096B  map_ids 4,5
6: cgroup_skb  tag 2a142ef67aaad174  gpl
        loaded_at 2019-05-16T14:20:23+0000  uid 0
        xlated 296B  jited 229B  memlock 4096B  map_ids 4,5
7: cgroup_skb  tag 7be49e3934a125ba  gpl
        loaded_at 2019-05-16T14:20:26+0000  uid 0
        xlated 296B  jited 229B  memlock 4096B  map_ids 6,7
8: cgroup_skb  tag 2a142ef67aaad174  gpl
        loaded_at 2019-05-16T14:20:26+0000  uid 0
        xlated 296B  jited 229B  memlock 4096B  map_ids 6,7
77: xdp  tag 8e351ef48840bc7c  gpl
        loaded_at 2019-05-17T14:33:49+0000  uid 0
        xlated 184B  jited 148B  memlock 4096B  map_ids 57
```

So that was a good deal of information returned by `bpftool` lets ignore the `cgroup_skb` entries which are used by the kernel for other utilities. The key here is there should be a `xdp` entry listed.

Now that we know our program is installed and operating lets take a look at the map objects we have to work with:

```
$ sudo bpftool map list
2: lpm_trie  flags 0x1
        key 8B  value 8B  max_entries 1  memlock 4096B
3: lpm_trie  flags 0x1
        key 20B  value 8B  max_entries 1  memlock 4096B
4: lpm_trie  flags 0x1
        key 8B  value 8B  max_entries 1  memlock 4096B
5: lpm_trie  flags 0x1
        key 20B  value 8B  max_entries 1  memlock 4096B
6: lpm_trie  flags 0x1
        key 8B  value 8B  max_entries 1  memlock 4096B
7: lpm_trie  flags 0x1
        key 20B  value 8B  max_entries 1  memlock 4096B
57: array  flags 0x0
        key 4B  value 16B  max_entries 1  memlock 4096B
```

Again we have a lot of info here, and for the time being lets again ignore the `lpm_trie` entries in the list and focus on the `array` entry at the bottom. This `array` entry is our BPF map that we have defined in `stats_kern.c` lets take a look at its contents:

```
$ sudo bpftool map dump id 57
key: 00 00 00 00  value: 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
Found 1 element
```

> Note in the above call take the `id` value from the output of `sudo bpftool map list`

so that output isn't exactly easy to read and is the raw bytes of the key and value stored in the BPF map, remember this particular definition had a `max_entries` of `1`. So lets try to pin this map to the filesystem and use the `stats_user` binary to pretty print the contents.

```
$ make
<-- snip -->

$ sudo bpftool map pin id 57 /sys/fs/bpf/counters
$ sudo ./stats_user
Overall:
        Packets: 0
        Bytes:   0 Bytes
```

That seems like a much better and easier on the eyes output for us. Congratulations you just pinned your first BPF map using `bpftool` and queried its data from a `libbpf` based application!

We aren't quite done yet, lets try to make this XDP program a bit faster by removing the calls to `__sync_fetch_and_add` which is a locking mechanism to keep multiple XDP programs updating our map from clobering each other.

Before moving on make sure to clean up:

```
$ sudo ip link set dev lo xdp off
$ sudo rm -f /sys/fs/bpf/counters
```

## `BPF_MAP_TYPE_ARRAY` vs `BPF_MAP_TYPE_PERCPU_ARRAY`
So in our current implementation we are using a `BPF_MAP_TYPE_ARRAY` which is a single instance array that all threads executing our XDP program share the same keys/values. This leads me to one of the very useful pieces of performance data regarding XDP, its `multi-threaded`. Because of the shared nature of `BPF_MAP_TYPE_ARRAY` if we want to update and manage data inside of one from XDP we need to ensure we are using locking. This is fine for the most part but can cause contention and performance issues in high throughput situations.

This is where `BPF_MAP_TYPE_PERCPU_ARRAY` and really any of the `PERCPU` variants of the BPF maps come into play. These variants have a shared key space but every CPU that is running the XDP program gets its own value for a given key. Meaning no locking is needed and the userspace needs to handle piecing things together to get the overall value for any given key.

So lets update our `stats_kern.c` and `stats_user.c` to handle working with a `BPF_MAP_TYPE_PERCPU_ARRAY`. Each one needs changes, the `stats_kern.c` file needs to be updated so that the BPF map definition has the proper type and that the `__sync_fetch_and_add` calls are replaced with just updating the fields of the returned `cnt` value directly.

The `stats_user.c` needs more indepth changes, but it will revolve around updating the `get_array_stats` function to handle passing in an array of `struct counters` into the call to `bpf_map_lookup_elem` instead of the `struct counters` pointer passed into the function.

> Note if you are struggling take a peek at `solution-2/stats_user.c` and `solution-2/stats_kern.c` for annotated solutions.

So we have updated the calls lets take a look at what has changed by following the process above:

```
$ make
<-- snip -->

$ sudo ip link set dev lo xdp obj stats_kern.o sec stats
$ sudo bpftool prog list
<-- snip -->
78: xdp  tag f43be0e89aa81e27  gpl
        loaded_at 2019-05-17T15:19:34+0000  uid 0
        xlated 160B  jited 134B  memlock 4096B  map_ids 58

$ sudo bpftool map list
<-- snip -->
58: percpu_array  flags 0x0
        key 4B  value 16B  max_entries 1  memlock 4096B

$ sudo bpftool map dump id 58
key:
00 00 00 00
value (CPU 00): 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
value (CPU 01): 00 00 00 00 00 00 00 00  00 00 00 00 00 00 00 00
Found 1 element
```

> Note in the above make sure you set the `id` value to the output of the previous calls in the above yours may be different.

So lets see whats different here, first off the call to `sudo bpftool map list` returned a slightly different output this time. The type of our BPF map is now `percpu_array` instead of just `array`, which is exactly what we want! Also as you can see above when we dump the map we still have a single key, but each CPU has its own value!

Lets pin this and now test out what happens with `stats_user`:

```
$ sudo bpftool map pin id 58 /sys/fs/bpf/counters
$ sudo ./stats_user
CPU: 0
        Packets: 0
        Bytes:   0 Bytes
CPU: 1
        Packets: 0
        Bytes:   0 Bytes
Overall:
        Packets: 0
        Bytes:   0 Bytes
```
