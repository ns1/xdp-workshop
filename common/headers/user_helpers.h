// SPDX-License-Identifier: GPL-2.0

#ifndef _USER_HELPERS_H
#define _USER_HELPERS_H

#include <bpf/bpf.h>
// #include <bpf/libbpf.h>
#include <errno.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>

#include "consts.h"
#include "structs.h"

static int get_ifindex(const char *raw_ifname)
{
    char ifname_buf[IF_NAMESIZE];
    char *ifname = NULL;

    if (strlen(raw_ifname) >= IF_NAMESIZE)
    {
        printf("ERR: Device name '%s' too long: must be less than %d characters\n",
               raw_ifname, IF_NAMESIZE);
        return -1;
    }
    ifname = (char *)&ifname_buf;
    strncpy(ifname, raw_ifname, IF_NAMESIZE);

    int if_index = if_nametoindex(ifname);
    if (if_index == 0)
    {
        printf("ERR: Device name '%s' not found err(%d): %s\n", raw_ifname, errno,
               strerror(errno));
        return -1;
    }

    return if_index;
}

int open_bpf_map(const char *file)
{
    int fd;

    fd = bpf_obj_get(file);
    if (fd < 0)
    {
        printf("ERR: Failed to open bpf map file: '%s' err(%d): %s\n",
               file, errno, strerror(errno));
        return -errno;
    }
    return fd;
}

static int get_action_stats(int fd)
{
    unsigned int num_cpus = bpf_num_possible_cpus();
    struct counters values[num_cpus];
    struct counters overall = {
        .bytes = 0,
        .packets = 0,
    };

    for (__u32 i = 0; i < XDP_MAX_ACTIONS; i++)
    {
        overall.bytes = 0;
        overall.packets = 0;

        if ((bpf_map_lookup_elem(fd, &i, values)) != 0)
        {
            printf("ERR: Failed to lookup map counter for action '%s' err(%d): %s\n",
                   action2str(i), errno, strerror(errno));
            return EXIT_FAIL_XDP_MAP_LOOKUP;
        }

        for (int j = 0; j < num_cpus; j++)
        {
            overall.bytes += values[j].bytes;
            overall.packets += values[j].packets;
        }
        printf("Action '%s':\n\tPackets: %llu\n\tBytes:   %llu Bytes\n\n",
               action2str(i), overall.packets, overall.bytes);
    }

    return EXIT_OK;
}

static int print_action_stats()
{
    int map_fd = open_bpf_map(COUNTER_MAP_PATH);
    if (map_fd < 0)
    {
        return EXIT_FAIL_XDP_MAP_OPEN;
    }
    return get_action_stats(map_fd);
}

static int set_rlimit()
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &r))
    {
        printf("ERR: failed to call setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY) err(%d): %s\n",
               errno, strerror(errno));
        return EXIT_FAIL_RLIMIT;
    }
    return EXIT_OK;
}

#endif // _USER_HELPERS_H