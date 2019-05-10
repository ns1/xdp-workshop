#ifndef _LAYER2_USER_H
#define _LAYER2_USER_H

#include <alloca.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <getopt.h>
#include <net/if.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "bpf_util.h"
#include "structs.h"

/* Exit codes */
#define EXIT_OK 0
#define EXIT_FAIL_GENERIC 1
#define EXIT_FAIL_OPTIONS 2

#define EXIT_FAIL_XDP_ATTACH 3
#define EXIT_FAIL_XDP_DETACH 4

#define EXIT_FAIL_XDP_MAP_OPEN 5
#define EXIT_FAIL_XDP_MAP_LOOKUP 6
#define EXIT_FAIL_XDP_MAP_UPDATE 7
#define EXIT_FAIL_XDP_MAP_PIN 8

#define EXIT_FAIL_RLIMIT 9

#define NUM_MAPS 2
#define MAP_DIR "/sys/fs/bpf"
#define COUNTER_MAP_PATH "/sys/fs/bpf/action_counters"
#define MAC_BLACKLIST_PATH "/sys/fs/bpf/mac_blacklist"

static const char *xdp_maps[NUM_MAPS] = {
    [0] = COUNTER_MAP_PATH,
    [1] = MAC_BLACKLIST_PATH,
};

static const char *xdp_action_names[XDP_MAX_ACTIONS] = {
    [XDP_ABORTED] = "XDP_ABORTED",
    [XDP_DROP] = "XDP_DROP",
    [XDP_PASS] = "XDP_PASS",
    [XDP_TX] = "XDP_TX",
    [XDP_REDIRECT] = "XDP_REDIRECT",
};

static const char *action2str(int action)
{
    if (action < XDP_MAX_ACTIONS)
    {
        return xdp_action_names[action];
    }
    return NULL;
}

static const char *doc = "XDP: Layer 2 firewall\n";

static const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"xdp-program", optional_argument, NULL, 'x'},
    {"attach", required_argument, NULL, 'a'},
    {"detach", required_argument, NULL, 'd'},
    {"stats", no_argument, NULL, 's'},
    {"insert", no_argument, NULL, 'i'},
    {"remove", no_argument, NULL, 'r'},
    {"mac-blacklist", required_argument, NULL, 'm'},
    {0, 0, NULL, 0}};

static const char *long_options_descriptions[8] = {
    [0] = "Display this help message.",
    [1] = "The file path to the xdp program to load.",
    [2] = "Attach the specified XDP program to the specified network device.",
    [3] = "Detach the specified XDP program from the specified network device.",
    [4] = "Print statistics from the already loaded XDP program.",
    [5] = "Insert the specified value into the blacklist.",
    [6] = "Remove the specified value from the blacklist.",
    [7] = "Insert/Remove the spcified MAC address to/from the blacklist. Must "
          "be in the form '00:00:00:00:00:00'.",
};

static void usage(char *argv[])
{
    int i;
    printf("%s\n", doc);
    printf("Usage: %s [options]\n\n", argv[0]);
    printf("Options:\n");

    for (i = 0; long_options[i].name != 0; i++)
    {
        printf(" -%c|--%-14s %s\n", long_options[i].val, long_options[i].name,
               long_options_descriptions[i]);
    }
    printf("\n");
}

/* This is needed due to getopt's optional_argument parsing:
 * https://stackoverflow.com/questions/1052746/getopt-does-not-parse-optional-arguments-to-parameters
 */
bool handle_optional_argument(int argc, char **argv)
{
    if (!optarg && optind < argc && NULL != argv[optind] &&
        '\0' != argv[optind][0] && '-' != argv[optind][0])
    {
        return true;
    }
    return false;
}

static int set_rlimit()
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &r))
    {
        printf("ERR: failed to call setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY) "
               "err(%d): %s\n",
               errno, strerror(errno));
        return EXIT_FAIL_RLIMIT;
    }
    return EXIT_OK;
}

int open_bpf_map(const char *file)
{
    int fd;

    fd = bpf_obj_get(file);
    if (fd < 0)
    {
        printf("ERR: Failed to open bpf map file: '%s' err(%d): %s\n", file, errno,
               strerror(errno));
        return -errno;
    }
    return fd;
}

static int get_percpu_stats(int fd)
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
        printf("Action '%s':\nPackets: %llu\nBytes:   %llu Bytes\n\n",
               action2str(i), overall.packets, overall.bytes);
    }

    return EXIT_OK;
}

#endif /* _LAYER2_USER_H */
