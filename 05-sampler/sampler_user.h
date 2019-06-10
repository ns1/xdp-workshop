// SPDX-License-Identifier: GPL-2.0

#ifndef _LAYER4_USER_H
#define _LAYER4_USER_H

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/perf_event.h>
#include <poll.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

#include "kernel/bpf_util.h"

#include "workshop/common.h"
#include "workshop/user/constants.h"
#include "workshop/user/map_helpers.h"
#include "workshop/user/options.h"
#include "workshop/user/prog_helpers.h"
#include "workshop/user/utils.h"

#include "common.h"

#define SAMPLES_PATH "/sys/fs/bpf/samples"
#define SAMPLE_RATE_PATH "/sys/fs/bpf/sample_rate"

static char *default_prog_path = "sampler_kern.o";
static char *default_section = "sampler";

static const char *doc = "XDP: Packet Sampler\n";

static const struct option long_options[] = {
    {"help", no_argument, NULL, 'h'},
    {"xdp-program", optional_argument, NULL, 'x'},
    {"xdp-section", optional_argument, NULL, 'n'},
    {"interface", required_argument, NULL, 'i'},
    {"stats", no_argument, NULL, 's'},
    {"print-packets", no_argument, NULL, 'p'},
    {"sample-rate", required_argument, NULL, 'r'},
    {0, 0, NULL, 0},
};

static const char *long_options_descriptions[] = {
    [0] = "Display this help message.",
    [1] = "The file path to the xdp program to load.",
    [2] = "The section name to load from the given xdp program.",
    [3] = "Attach the specified XDP program to the specified network device.",
    [4] = "Detach the specified XDP program from the specified network device.",
    [5] = "Print statistics from the already loaded XDP program.",
    [6] = "Print captured packets.",
    [7] = "Set the desired sample rate.",
};

struct perf_metadata
{
    __u16 cookie;
    __u16 length;
    __u8 data[MAX_SAMPLE_SIZE];
} __packed;

struct perf_event_sample
{
    struct perf_event_header header;
    __u32 size;
    char data[];
};

#endif /* _LAYER4_USER_H */
