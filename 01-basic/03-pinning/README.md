# Pinning
In this exercise we are going dive into how we can leverage `libbpf` in order to facilitate interacting with and managing XDP programs. As opposed to leveraging `bpftool`/`iproute2`, which while useful and entirely capable is combursome to use.

## `libbpf`
Before we jump into the code, lets make sure we are up to date with what `libbpf` is. The library is part of the linux kernel and is a set of structures, functions, macros, and helpers for interacting with and managing BPF in general. It can be used with standard BPF as well as XDP and it likely the main entrypoint to manging XDP/BPF programatically.

There are some key functions that we will be leveraging throughout the rest of this workshop and likely will be used in pretty much every XDP managment program.
- `bpf_obj_get` - loads a bpf object from a file.
- `bpf_map_update_elem` + `bpf_map_lookup_elem` - either updates or queries for a value in a BPF map object.
- `bpf_prog_load` - loads a bpf program from an elf object file on disk.
- `bpf_set_link_xdp_fd` - attaches a loaded XDP program to a network interface.
- `bpf_object__pin_maps` + `bpf_object__unpin_maps` - either pins or unpins the map objects from a loaded BPF object to disk.

### `bpf_obj_get`
This function is how we load BPF map objects from disk that are defined in the various XDP programs we will be working with through out the workshop. This is the key function that allows for a user space application to interact with a BPF map to either query for information set by an XDP program or augment an XDP programs behavior.

This is used in conjuction with `bpf_map_update_elem` and `bpf_map_lookup_elem` as it is what provides the file descriptor both of these `bpf_map_*` functions require.

### `bpf_map_update_elem` and `bpf_map_lookup_elem`
These both offer the interfaces in which a user space application actually interacts with the data inside of a BPF map. They can be used in many ways, for instance the `bpf_map_update_elem` can be used to update only if it exists and error otherwise, or preform an upsert based on the flags provided.

Really these two functions lay the foundation for making dynamic XDP programs that can be augmented on the fly without being recompiled.

### `bpf_prog_load` and `bpf_set_link_xdp_fd`
These, in combination, represent the interface for attaching and detaching an XDP program from a network interface. The `bpf_prog_load` function is what is used to actually load the `elf_bpf` object file that is complied using `llvm` + `clang` off of disk and parsing it into the required format for the kernel to operate on.

The `bpf_set_link_xdp_fd` is what handles taking the loaded bpf object and attaches it to the given interface. This is where the XDP verifier is run on the program we loaded and the kernel ensures that the program will operate within the constrains of the BPF sandbox.

### `bpf_object__pin_maps` and `bpf_object__unpin_maps`
These both handle the tedious taks of pinning and unpinning the various maps that are represented in a loaded bpf object. Essentially these are courtesy functions to help facilitate the process of using `bpftool` to list and then pin the various maps in a running XDP program.

## Let us get our hands dirty once again
So at this point lets take a close look at the files in this directory to see `libbpf` in action for the first time.

### `pinning_kern.c`
First lets look at the `pinning_kern.c` file. Which will look very reminiscent of the last XDP program we looked at in the previous section `stats_kern.c`. The real change here is that we are enabling this new XDP program to by dynamically updated to return different return codes.

The key to this is the inclusion of the `action` bpf map:

```
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
```

As you can see this is essentially a copy paste from the bpf map definition from `stats_kern` but it will be used in a ver different way. If you look at the function `get_action()` you can see how it works:

```
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
```

As you can see we are using the `action` map to determine the return code of our XDP program. This is a albeit simple but powerful setup that will allow us to dynamically change how this program interacts with packets.

### `pinning_user.c`
Now lets take a look at the user space application that we will be using to control our new `pinning_kern` XDP program. This is where the bulk of our time will spent, but lets focus on a few key components of this application.

#### `handle_action(const char *str_action)`
This function handles taking in a string version of the action we want to have our XDP program return, such as 'XDP_PASS' or 'XDP_DROP'.

> WARNING: Do NOT specify XDP_TX or XDP_REDIRECT here it will.... break the network interface :)

The idea here is we are leveraging the same methodology we did in `stats_user.c` in the previous section to open the BPF map itself, and then calling `bpf_map_update_elem` to update the action that we want to return on the fly.

One thing of note here is that this is a case where using a `PERCPU` variant of the the BPF map objects is likely not what you want to do.

#### `detach(int if_index, char *prog_path)`
This function handles removing the XDP program **and** unpinning the maps it contains from the `/sys/fs/bpf` filesystem. Essentially this is combining the steps we ran through in the previous section namely:

```
$ sudo ip set link dev lo xdp off
$ sudo rm -f /sys/fs/bpf/counters
```

into a single function call that handles everything automatically.

It does this by leveraging the combination of:
- `bpf_prog_load`
- `bpf_set_link_xdp_fd`
- `bpf_object__unpin_maps`

The reason we need to specify the program file path and we did not have to do so when using `iproute2` like in the previous section, is because `libbpf` requires a handle to the BPF object the file contains to properly cleanup the map objects.

#### `attach(int if_index, char *prog_path)`
This function handles attaching a given XDP program to a given network interface. This also handles the process of pinning all defined maps to the `/sys/fs/bpf` filesystem. This represents the same workflow as we did in the last section namely:

```
$ sudo ip link set dev lo xdp obj ${object file} sec ${section name}
$ sudo bpftool map list
<-- snip -->
$ sudo bpftool map pin id ${map id from above} /sys/fs/bpf/${map name}
```

into a single function call that handles everything automatically.

It does this by leveraging the combination of:
- `bpf_prog_load`
- `bpf_set_link_xdp_fd`
- `bpf_object__unpin_maps`

#### Lets see how this all works together
At this point we should have a good handle on how things operate using `libbpf` lets see it in action:

```
$ make
$ sudo ./pinning_user --attach lo
$ sudo ls -alh /sys/fs/bpf
total 0
drwx-----T 3 root root 0 May 17 18:52 .
drwxr-xr-x 9 root root 0 May 16 22:41 ..
-rw------- 1 root root 0 May 17 18:52 action
-rw------- 1 root root 0 May 17 18:52 action_counters
<-- snip -->

$ sudo ./pinning_user --stats
Action 'XDP_ABORTED':
        Packets: 0
        Bytes:   0 Bytes

Action 'XDP_DROP':
        Packets: 0
        Bytes:   0 Bytes

Action 'XDP_PASS':
        Packets: 0
        Bytes:   0 Bytes

Action 'XDP_TX':
        Packets: 0
        Bytes:   0 Bytes

Action 'XDP_REDIRECT':
        Packets: 0
        Bytes:   0 Bytes
```

You now have attached your first XDP program and pinned maps to the `/sys/fs/bpf` for the first time using `libbpf` congrats!

Lets see how it works in a new terminal go ahead and start a ping aginst localhost:

```
$ ping localhost
```

You should see no output and that is because all packets are being dropped. Go ahead in your first terminal and run the following:

```
$ sudo ./pinning_user --set-action XDP_PASS
```

Once you complete the above command your ping command should instantly start showing output of ping's flowing in both directions! You just operated your first dynamic XDP program!

#### Extra Credit
Go ahead and play with setting the various different return codes using:

```
$ sudo ./pinning_user --set-action ${action}
```

and using:

```
$ sudo ./pinning_user --stats
```

To monitor what the XDP program is doing while your ping is running.

> WARNING again do **not** set the action to XDP_TX or XDP_REDIRECT... you've been warned. :)