// SPDX-License-Identifier: GPL-2.0

#ifndef _SAMPLER_KERN_H
#define _SAMPLER_KERN_H

#include <linux/bpf.h>
#include <linux/types.h>

#include "kernel/bpf_helpers.h"

#include "common.h"
#include "workshop/common.h"
#include "workshop/kern/bpf_debug.h"
#include "workshop/kern/action_counters.h"

/*
    'perf_metadata' represents the data we are passing along to the bpf_perf_event_output function along with the,
    actual packet data. This is used in userspace to determine the length of the data that is sent into userspace from the 
    XDP program as well as to determine if the perf event is indeed from our XDP program. 

    The 'cookie' field is an arbitrary key of sorts that we can use to verify that the perf event itself is coming froma a source that make sense,
    and that we should dissect the event in userspace.

    The 'length' field is a note to tell the userspace application how much data was included in the perf event so that it knows how much data to parse.

    Note that we are not actually passing in the data itself here, and that is handled by the kernel and is actually made available via a perf ring.
*/
struct perf_metadata
{
    __u16 cookie;
    __u16 length;
} __packed;

#endif // _SAMPLER_KERN_H
