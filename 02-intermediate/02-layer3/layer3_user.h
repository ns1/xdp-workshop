#ifndef _LAYER3_USER_H
#define _LAYER3_USER_H

#include <alloca.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <unistd.h>

#include "bpf_util.h"
#include "common.h"
#include "consts.h"
#include "options.h"
#include "structs.h"
#include "user_helpers.h"
#include "xdp_prog_helpers.h"

#define MAC_BLACKLIST_PATH "/sys/fs/bpf/mac_blacklist"
#define V4_BLACKLIST_PATH "/sys/fs/bpf/v4_blacklist"
#define V6_BLACKLIST_PATH "/sys/fs/bpf/v6_blacklist"

static const char *doc = "XDP: Layer 3 firewall\n";

static const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"xdp-program", optional_argument, NULL, 'x'},
    {"attach", required_argument, NULL, 'a'},
    {"detach", required_argument, NULL, 'd'},
    {"stats", no_argument, NULL, 's'},
    {"insert", no_argument, NULL, 'i'},
    {"remove", no_argument, NULL, 'r'},
    {"mac-blacklist", required_argument, NULL, 'm'},
    {"v4-blacklist", required_argument, NULL, '4'},
    {"v6-blacklist", required_argument, NULL, '6'},
    {0, 0, NULL, 0}};

static const char *long_options_descriptions[10] = {
    [0] = "Display this help message.",
    [1] = "The file path to the xdp program to load.",
    [2] = "Attach the specified XDP program to the specified network device.",
    [3] = "Detach the specified XDP program from the specified network device.",
    [4] = "Print statistics from the already loaded XDP program.",
    [5] = "Insert the specified value into the blacklist.",
    [6] = "Remove the specified value from the blacklist.",
    [7] = "Insert/Remove the spcified MAC address to/from the blacklist. Must "
          "be in the form '00:00:00:00:00:00'.",
    [8] = "Insert/Remove the specified IPv4 prefix to/from the blacklist. Must "
          "be in CIDR notation.",
    [9] = "Insert/Remove the specified IPv6 prefix to/from the blacklist. Must "
          "be in CIDR notation.",
};

#endif /* _LAYER3_USER_H */
