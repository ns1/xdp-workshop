// SPDX-License-Identifier: GPL-2.0

#ifndef _COMMON_H
#define _COMMON_H

#define MAX_CPUS 32
#define MAX_SAMPLE_SIZE 65535

#ifndef XDP_MAX_ACTIONS
#define XDP_MAX_ACTIONS (XDP_REDIRECT + 1)
#endif

#ifndef XDP_CONTINUE
#define XDP_CONTINUE XDP_MAX_ACTIONS
#endif

#endif // _COMMON_H