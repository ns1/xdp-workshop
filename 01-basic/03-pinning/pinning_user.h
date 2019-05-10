#ifndef _PINNING_USER_H
#define _PINNING_USER_H

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
#include "common.h"

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
#define ACTION_MAP_PATH "/sys/fs/bpf/action"

static const char *xdp_maps[NUM_MAPS] = {
    [0] = ACTION_MAP_PATH,
    [1] = COUNTER_MAP_PATH,
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

static int str2action(const char *action)
{
    int i;
    for (i = 0; i < XDP_MAX_ACTIONS; i++)
    {
        if (strcmp(xdp_action_names[i], action) == 0)
        {
            return i;
        }
    }
    return -1;
}

static const char *doc = "XDP: Map pinning and loading/unloading\n";

static const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"xdp-program", optional_argument, NULL, 'x'},
    {"attach", required_argument, NULL, 'a'},
    {"detach", required_argument, NULL, 'd'},
    {"stats", no_argument, NULL, 's'},
    {"set-action", required_argument, NULL, 'e'},
    {0, 0, NULL, 0}};

static const char *long_options_descriptions[6] = {
    [0] = "Display this help message.",
    [1] = "The file path to the xdp program to load.",
    [2] = "Attach the specified XDP program to the specified network device.",
    [3] = "Detach the specified XDP program from the specified network device.",
    [4] = "Print statistics from the already loaded XDP program.",
    [5] = "Set the XDP action for the XDP program to return.",
};

static void usage(char *argv[])
{
    int i;
    printf("%s\n", doc);
    printf("Usage: %s [options]\n\n", argv[0]);
    printf("Options:\n");

    for (i = 0; long_options[i].name != 0; i++)
    {
        printf(" -%c|--%-12s %s\n", long_options[i].val, long_options[i].name,
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

#endif /* _PINNING_USER_H */
