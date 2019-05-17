// SPDX-License-Identifier: GPL-2.0

#ifndef _STRUCTS_H
#define _STRUCTS_H

#include <linux/types.h>

struct counters
{
    __u64 packets;
    __u64 bytes;
};

#endif