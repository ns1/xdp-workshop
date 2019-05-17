// SPDX-License-Identifier: GPL-2.0

#ifndef _STATS_COMMON_H
#define _STATS_COMMON_H

#include <linux/types.h>

struct counters
{
    __u64 packets;
    __u64 bytes;
};

#endif // _STATS_COMMON_H
