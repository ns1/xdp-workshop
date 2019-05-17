// SPDX-License-Identifier: GPL-2.0

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "bpf_util.h"
#include "common.h"

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

static __u32 get_array_stats(int fd, struct counters *overall)
{
    __u32 counter_idx = 0;
    if ((bpf_map_lookup_elem(fd, &counter_idx, overall)) != 0)
    {
        printf("ERR: Failed to open bpf map object fd '%d' err(%d): %s\n",
               fd, errno, strerror(errno));
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

    struct counters overall = {
        .packets = 0,
        .bytes = 0,
    };
    if (get_array_stats(fd, &overall) < 0)
    {
        return 1;
    }

    printf("Overall:\n");
    printf("\tPackets: %llu\n", overall.packets);
    printf("\tBytes:   %llu Bytes\n", overall.bytes);
    return 0;
}
