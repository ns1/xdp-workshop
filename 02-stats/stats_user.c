// SPDX-License-Identifier: GPL-2.0

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "kernel/bpf_util.h"

#include "common.h"

/*
    The function 'open_bpf_map' handles opening a pinned BPF map file. On error it will return
    the negative error code from the function 'bpf_obj_get'. Otherwise it will return a file descriptor
    pointing to the pinned BPF map file, which can be used with 'bpf_map_lookup_elem'.
*/
int open_bpf_map(const char *file)
{
    int fd;

    fd = bpf_obj_get(file);
    if (fd < 0)
    {
        printf("ERR: Failed to open bpf map file '%s' err(%d): %s\n",
               file, errno, strerror(errno));
        return -errno;
    }
    return fd;
}

/*
    The function 'get_array_stats' operates on a BPF map of type 'BPF_MAP_TYPE_ARRAY' and handles,
    pulling a single member from the supplied file descriptor. On error it will return the negative error
    code from the function 'bpf_map_lookup_elem'. Otherwise it will return '0' and fill in the supplied
    'struct counters' pointer with the data stored inside the BPF map.
*/
static __u32 get_array_stats(int fd, struct counters *overall)
{
    /*
        We have a single key/value stored in the map so the index that we are going to be interrogating in this
        map is always '0'.
    */
    __u32 counter_idx = 0;

    /*
        We call 'bpf_map_lookup_elem' which in userspace takes the file descriptor to the BPF map we are interrogating,
        a pointer the to the key we are looking for, and a pointer to a struct to hold the corresponding value if it exists.

        If the value doesn't exist, or the file descriptor is not for the correct map then this runtion will return a non '0' error
        code and set errno.
    */
    if ((bpf_map_lookup_elem(fd, &counter_idx, overall)) != 0)
    {
        printf("ERR: Failed to open bpf map object fd '%d' err(%d): %s\n",
               fd, errno, strerror(errno));
        return -errno;
    }
    return 0;
}

int main(int argc, char **argv)
{
    /*
        First we want to open our freshly pinned map, at the path we set using 'bpftool'.
    */
    int fd = open_bpf_map("/sys/fs/bpf/counters");
    if (fd < 0)
    {
        return 1;
    }

    /*
        Once we have sucessfully opened our BPF map we want to get the stats contained within and then print them
        to stdout for consumption.
    */
    struct counters overall = {
        .packets = 0,
        .bytes = 0,
    };
    if (get_array_stats(fd, &overall) < 0)
    {
        return 1;
    }

    /*
        We are using printf here as an easy way to print this data in a formatted way, there are other more efficient/performant ways
        to accomplish this, but for the purposes of this workshop its more than enough.
    */
    printf("Overall:\n");
    printf("\tPackets: %llu\n", overall.packets);
    printf("\tBytes:   %llu Bytes\n", overall.bytes);
    return 0;
}
