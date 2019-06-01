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

#include "kernel/bpf_util.h"

#include "workshop/common.h"
#include "workshop/user/constants.h"
#include "workshop/user/map_helpers.h"
#include "workshop/user/options.h"
#include "workshop/user/prog_helpers.h"
#include "workshop/user/utils.h"

// #include "common.h"

static char *default_prog_path = "tcbit_kern.o";
static char *default_section = "tcbit";

static const char *doc = "XDP: TCBit Auto Responder\n";

static const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"xdp-program", optional_argument, NULL, 'x'},
    {"xdp-section", optional_argument, NULL, 'n'},
    {"attach", required_argument, NULL, 'a'},
    {"detach", required_argument, NULL, 'd'},
    {"stats", no_argument, NULL, 's'},
    {0, 0, NULL, 0},
};

static const char *long_options_descriptions[] = {
    [0] = "Display this help message.",
    [1] = "The file path to the xdp program to load.",
    [2] = "The section name to load from the given xdp program.",
    [3] = "Attach the specified XDP program to the specified network device.",
    [4] = "Detach the specified XDP program from the specified network device.",
    [5] = "Print statistics from the already loaded XDP program.",
};

#endif /* _LAYER4_USER_H */
