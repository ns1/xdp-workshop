# xdpfw
This exercise is going to explore a real use case for XDP, as well as dive into some of the more advanced BPF map types that are available. Specifically digging into how to leverage `BPF_MAP_TYPE_HASH` and `BPF_MAP_TYPE_LPM_TRIE` as well as how to leverage limited looping in your XDP applications.

## `BPF_MAP_TYPE_HASH`/`BPF_MAP_TYPE_PERCPU_HASH`
Up until this point we have been exclusively relying on array based BPF maps. So lets take a close look at the hash variant of the BPF maps. They operate in a very similar way to array's however they allow for specifying whether or not they are "pre-allocated" by the kernel. Meaning you can control whether or not the entire key space of the hash is filled out by the kernel when the map itself is loaded and attached to a network device.

The way this is controlled is by leveraging the `map_flags` field of the `bpf_map_def` struct as shown bellow:

```
struct bpf_map_def SEC("maps") mac_blacklist = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = ETH_ALEN,
    .value_size = 1,
    .max_entries = MAC_BLACKLIST_MAX_ENTRIES,
    .map_flags = BPF_F_NO_PREALLOC,
};
```

As one can see there isn't much different here than from the other BPF map definitions that exist in the previous sections that are arrays, the only real difference is the `type` and `map_flags` fields being set appropriately.

So one thing that we need to keep in mind is that the hash variant of BPF maps rely on byte hashing to find matches, where as the array variants do what you would think and match based on indexes. This is a key difference that allows for some very interesting matching capabilities. Also something that we have not directly called out yet is that if you notice we never set the "type" of the fields for either the keys or the values in a BPF map. Instead we are just specifying their "size". This is a crucial thing to note, and means that types are essentially entirely ignored and all that matters in the end is that the byte layout of the structs are consistent.

## For loops and you
So you will hear a lot of people say that you are unable to loop in a BPF program, and they aren't entirely right or wrong. The real key here is that you can't have an arbitrarilly long or indeterminately long loop inside of a BPF program. So what does that mean? Well it means that at _compile_ time you must be able to absolutely confirm the maximum number of iterations, and therefore you must be able to **unroll** the loop. This is important because it means that you can loop as long as your explicit about how many times you could potentially loop.

The rationale regarding this limitation is quite straight forward. First and foremost this goes back to the BPF verifier and the fact that it checks the number of instructions in the given BPF program. If your loop wasn't explicitly ended then how would the verifier know how many instructions the program is made up of? Potentially more importantly you wouldn't want to base a loop off the data contained within a packet because of the possibility that a malicious actor could use that knowledge and potentially cause a loop orders of magnitude larger than you were initially expecting, decimating performance of your networking hardware.

> Remember XDP programs execute once for _every_ packet seen.

With the above said it is still sometimes useful to have small loops in your BPF and XDP programs, and thats mostly to cleanup redudant code like seen in the ethernet header parser in this exercise reproduced bellow:

```
#pragma unroll
    for (int i = 0; i < 2; i++)
    {
        /*
            Check to see if the next in this packet is a vlan header, i.e. either a 8021Q or 8021AD protocol header.
        */
        if (ctx->nh_proto == ETH_P_8021Q || ctx->nh_proto == ETH_P_8021AD)
        {
            /*
                Preform the same process as the raw ethernet header above to ensure get to the next header.
            */
            struct vlan_hdr *vlan = ctx->data_start + ctx->nh_offset;

            /*
                You will see this particular snippet of code over and over and over again throughout all XDP/eBPF programs.
            */
            if (vlan + 1 > ctx->data_end)
            {
                return XDP_DROP;
            }

            ctx->nh_offset += sizeof(*vlan);
            ctx->nh_proto = bpf_ntohs(vlan->h_vlan_encapsulated_proto);
        }
    }
```

The above code is unwrapping a packets vlan headers, which could easily be done as two separate calls but this is subjectively easier to reason about than duplicating the loop code twice in the code.

## `BPF_MAP_TYPE_LPM_TRIE`
This map type is particularly useful for matching on IP address prefixes or really any prefix that one can think of that can be represented by a trie structure. The general idea behind them is that the matching function preforms a longest prefix match on the supplied key to see if the value currently exists in the map. The actual algorithm used in this matching is out of the scope of this workshop, however it does mean that we can use this BPF map type to efficiently match on large numbers of IP address prefixes for both IPv4 and IPv6.

In this case the structure of the key does matter to the algorithm and the kernel sources have the structure defined as:

```
struct bpf_lpm_trie_key {
	__u32	prefixlen;	/* up to 32 for AF_INET, 128 for AF_INET6 */
	__u8	data[0];	/* Arbitrary size */
};
```

There are a few things of note here though, first off the default key struct doesn't have a data length, and if you remember from the previous exercises in this workshop you are unable to call `malloc`, or any of its variants within an XDP program. So in order to properly leverage this struct from XDP you are left with two options, create a wrapper struct that includes padding for the length of data that you would want similar to something like this:

```
struct lpm_v4_key {
    struct bpf_lpm_trie_key lpm;
    __u8 padding[4];
} 
```

or you can create a matching struct with the correct data length, which is what we will be doing in this workshop like so:

```
struct lpm_v4_key
{
    __u32 prefixlen;
    __u8 address[4];
};
```

Both of the above structs will actually end up looking the same at a byte level, and the latter was choosen arbitrarilly to improve clarity of what was happening in the code. As an aside the IPv6 variants of the above are precisely the same other than the address/data lengths being `16` instead of `4`.

## Hash key complexity
So in the layer 4 parser and blacklist section of this exercise we have a relatively complex key type that we are using to match on source/destination ports for both UDP and TCP, reproduced bellow:

```
struct port_key
{
    enum port_type type;
    enum port_protocol proto;
    __u32 port;
};
```

This is an example where you are not limited in what you want to match on and you can make arbitrarily complex types to match on. This significantly increases the capabilities of the HASH map and its variants. There is a caveat though, this match is tsill done based on the byte structure of the type itself, so for instance you may notice that it isn't necessary to use a `__u32` as the port field here. While that is entirely true if we used a `__u16` something odd happens under the hood. The structs size becomes `10` bytes, which you may or may not know is a very odd size for a struct, and in actuality would end up being `12` once compiled and used. The reason for this is byte boundries and CPU architecture. At a very high level this is because a `x86_64` CPU is much better at handing 32bit or 64bit offsets than it is any other size value. So unless explicitly told otherwise everything is considered to be one of those two sizes.

Now what does this actually mean in practice? Well if you change that port field to `__u16` everything will compile and even attach to the device, but you will notice you will get odd results when trying to blacklist ports, everything from matching incorrect ports to not matching at all. Which is because of the 2 extra bytes added onto the end of the port_key struct when used which may or may not be zeroed out memory.

At the end of the day it is important to keep in mind that you are working in C and directly within the kernel.

## So why would we do this?
Considering this entire section amounts to hundreds of lines of C code, and a healthy number of caveats. Why would you use XDP? considering you could do everything this particular exercise does in this single command:

```
$ sudo iptables -A INPUT -s 10.0.0.0/8 -p tcp -m --dport 53 -j DROP
```

The short answer is we haven't even scratched the surface of what XDP is capable of and in the next sections I hope I can prove that to you. The slightly longer answer is that XDP is just faster than iptables could ever be because of where its injected, XDP operates in the best case on the hardware of the network device itself and in the worst case at the drive interface layer of the kernel.
