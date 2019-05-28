// SPDX-License-Identifier: GPL-2.0

#ifndef _LAYER4_USER_H
#define _LAYER4_USER_H

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
#define PORT_BLACKLIST_PATH "/sys/fs/bpf/port_blacklist"

static char *default_prog_path = "xdpfw_kern.o";
static char *default_section = "xdpfw";

static const char *doc = "XDP: Basic firewall\n";

static const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"xdp-program", optional_argument, NULL, 'x'},
    {"xdp-section", optional_argument, NULL, 'n'},
    {"attach", required_argument, NULL, 'a'},
    {"detach", required_argument, NULL, 'd'},
    {"stats", no_argument, NULL, 's'},
    {"insert", no_argument, NULL, 'i'},
    {"remove", no_argument, NULL, 'r'},
    {"mac-blacklist", required_argument, NULL, 'm'},
    {"v4-blacklist", required_argument, NULL, '4'},
    {"v6-blacklist", required_argument, NULL, '6'},
    {"dest-port", required_argument, NULL, 't'},
    {"src-port", required_argument, NULL, 'c'},
    {"proto", required_argument, NULL, 'p'},
    {0, 0, NULL, 0}};

static const char *long_options_descriptions[] = {
    [0] = "Display this help message.",
    [1] = "The file path to the xdp program to load.",
    [2] = "The section name to load from the given xdp program.",
    [3] = "Attach the specified XDP program to the specified network device.",
    [4] = "Detach the specified XDP program from the specified network device.",
    [5] = "Print statistics from the already loaded XDP program.",
    [6] = "Insert the specified value into the blacklist.",
    [7] = "Remove the specified value from the blacklist.",
    [8] = "Insert/Remove the spcified MAC address to/from the blacklist. Must "
          "be in the form '00:00:00:00:00:00'.",
    [9] = "Insert/Remove the specified IPv4 prefix to/from the blacklist. Must "
          "be in CIDR notation.",
    [10] = "Insert/Remove the specified IPv6 prefix to/from the blacklist. Must "
           "be in CIDR notation.",
    [11] = "Insert/Remove the specified destination port to the blacklist.",
    [12] = "Insert/Remove the specified source port to the blacklist.",
    [13] = "Set the protocol for the specified source/destination port.",
};

#endif /* _LAYER4_USER_H */
