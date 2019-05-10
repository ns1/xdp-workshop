/* SPDX-License-Identifier: GPL-2.0 */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "bpf_util.h"
#include "common.h"

// open_bpf_map opens a pinned bpf map based on the supplied filename.
int open_bpf_map(const char *file)
{
    int fd;

    fd = bpf_obj_get(file);
    if (fd < 0)
    {
        printf("ERR: Failed to open bpf map file:%s err(%d):%s\n", file, errno,
               strerror(errno));
        return -errno;
    }
    return fd;
}

// static __u64 get_percpu_stats(int fd, __u32 key) {
//    /* For percpu maps, userspace gets a value per possible CPU */
//    // unsigned int nr_cpus = bpf_num_possible_cpus();
//    // __u64 values[nr_cpus];
//    // __u64 sum = 0;
//    // int i;
//
//}

static __u32 get_array_stats(int fd, struct counters *counters)
{
    __u32 counter_idx = 0;
    if ((bpf_map_lookup_elem(fd, &counter_idx, counters)) != 0)
    {
        printf("ERR: Failed to open bpf map object fd: %d err(%d):%s\n", fd, errno,
               strerror(errno));
        return -1;
    }
    return 0;
}

int main(int argc, char **argv)
{
    int fd = open_bpf_map("/sys/fs/bpf/counters");
    if (fd < 0)
    {
        return 1;
    }

    struct counters cnt;
    if (get_array_stats(fd, &cnt) < 0)
    {
        return 1;
    }

    printf("Packets: %llu\n", cnt.packets);
    printf("Bytes:   %llu Bytes\n", cnt.bytes);
    return 0;
}
