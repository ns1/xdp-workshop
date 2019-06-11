// SPDX-License-Identifier: GPL-2.0

#ifndef _BPF_DEBUG_H
#define _BPF_DEBUG_H

#include <linux/bpf.h>

#include "kernel/bpf_helpers.h"

#define bpf_debug(fmt, ...)                                        \
    ({                                                             \
        char ____fmt[] = fmt;                                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), ##__VA_ARGS__); \
    })

#endif // _BPF_DEBUG_H
