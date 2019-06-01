// SPDX-License-Identifier: GPL-2.0

#ifndef _CONSTANTS_H
#define _CONSTANTS_H

#include <linux/bpf.h>

/* Exit codes */
#define EXIT_OK 0
#define EXIT_FAIL_GENERIC 1
#define EXIT_FAIL_OPTIONS 2

#define EXIT_FAIL_XDP_ATTACH 3
#define EXIT_FAIL_XDP_DETACH 4

#define EXIT_FAIL_XDP_MAP_OPEN 5
#define EXIT_FAIL_XDP_MAP_LOOKUP 6
#define EXIT_FAIL_XDP_MAP_UPDATE 7
#define EXIT_FAIL_XDP_MAP_DELETE 8
#define EXIT_FAIL_XDP_MAP_PIN 9

#define EXIT_FAIL_RLIMIT 10

#define MAP_DIR "/sys/fs/bpf"
#define COUNTER_MAP_PATH "/sys/fs/bpf/action_counters"

#ifndef XDP_MAX_ACTIONS
#define XDP_MAX_ACTIONS (XDP_REDIRECT + 1)
#endif

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

#endif // _CONSTANTS_H