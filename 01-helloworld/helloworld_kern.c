// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>

#include "bpf_helpers.h"

/*
    The function bpf_debug will print messages to '/sys/kernel/debug/tracing/trace_pipe'.

    Try running 'sudo cat /sys/kernel/debug/tracing/trace_pipe' and then attaching any of these xdp programs.
*/
#define bpf_debug(fmt, ...)                        \
    ({                                             \
        char ____fmt[] = fmt;                      \
        bpf_trace_printk(____fmt, sizeof(____fmt), \
                         ##__VA_ARGS__);           \
    })

SEC("xdp_abort")
int xdp_abort_fn(struct xdp_md *ctx)
{
    /*
        This action will increment a specific exception counter that will allow for
        helpful debugging.
    */

    bpf_debug("Aborting packet!\n");

    return XDP_ABORTED;
}

SEC("xdp_drop")
int xdp_drop_fn(struct xdp_md *ctx)
{
    /*
        This action will drop the current packet and move onto the next one in line.
    */

    bpf_debug("Dropping packet!\n");

    return XDP_DROP;
}

SEC("xdp_pass")
int xdp_pass_fn(struct xdp_md *ctx)
{
    /*
        This action will inform the kernel to continue processing this packet,
        as if the xdp program didn't exist.
    */

    bpf_debug("Passing packet to kernel!\n");

    return XDP_PASS;
}

/*
    We are ignoring two of the available XDP actions 'XDP_TX' and 'XDP_REDIRECT'
    for now as they are for advanced usecases.

    This is the full list of possible XDP return codes (actions) pulled from
    $(LINUX v5.0)/include/uapi/linux/bpf.h

    enum xdp_action {
        XDP_ABORTED = 0,
        XDP_DROP,
        XDP_PASS,
        XDP_TX,
        XDP_REDIRECT,
    };
*/

char _license[] SEC("license") = "GPL";
