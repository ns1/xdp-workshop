// SPDX-License-Identifier: GPL-2.0

#include <linux/in.h>
#include <linux/in6.h>

#include "kernel/bpf_endian.h"

#include "tcbit_kern.h"
#include "tcbit_kern_parsers.h"
#include "tcbit_kern_utils.h"

/*
    'csum_update' is used to update the layer 3 checksum for IPv4 and the layer 4 UDP checksum.

    The purpose of this code is to ensure that the changes we are making to the packet data throughout this program are properly
    handled by the networking devices between the host running the XDP program and the client that made the original request.
*/
static __always_inline void csum_update(__u16 *csum, __u32 from, __u32 to)
{
    __u32 sum, csum_c, from_c, res, res2, ret, ret2;

    csum_c = ~((__u32)*csum);
    from_c = ~from;
    res = csum_c + from_c;
    ret = res + (res < from_c);

    res2 = ret + to;
    ret2 = res2 + (res2 < to);

    sum = ret2;
    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    *csum = (__u16)~sum;
}

/*
    'swap_mac' handles swapping the source/destination MAC addresses of this packet, and is required since we are operating on raw packets
    and once the packet is transmitted by XDP_TX there will be no further proccessing on the packet other than it being sent to the TX queue
    of the device we are bound to.
*/
static __always_inline void swap_mac(struct context *ctx)
{
    __u8 temp[6];
    __builtin_memcpy(temp, ctx->eth->h_dest, sizeof(temp));
    __builtin_memcpy(ctx->eth->h_dest, ctx->eth->h_source, sizeof(temp));
    __builtin_memcpy(ctx->eth->h_source, temp, sizeof(temp));
}

/*
    'swap_ip' handles swapping the source/destination IP addresses for either an IPv4 or IPv6 packet and in the end operates very similarlly to the
    'swap_mac' function above with the biggest difference being that it handles updating the TTL of the IP headers so that the packets we send
    don't prematurely expire before they make it back to the original client.
*/
static __always_inline void swap_ip(struct context *ctx)
{
    if (ctx->v4)
    {
        __be32 temp;
        __builtin_memcpy(&temp, &ctx->v4->daddr, sizeof(temp));
        __builtin_memcpy(&ctx->v4->daddr, &ctx->v4->saddr, sizeof(temp));
        __builtin_memcpy(&ctx->v4->saddr, &temp, sizeof(temp));

        __u8 old_ttl = ctx->v4->ttl;
        ctx->v4->ttl = 64;

        csum_update(&ctx->v4->check, old_ttl, ctx->v4->ttl);
    }
    else if (ctx->v6)
    {
        struct in6_addr temp;
        __builtin_memcpy(&temp, &ctx->v6->daddr, sizeof(temp));
        __builtin_memcpy(&ctx->v6->daddr, &ctx->v6->saddr, sizeof(temp));
        __builtin_memcpy(&ctx->v6->saddr, &temp, sizeof(temp));

        ctx->v6->hop_limit = 64;
    }
}

/*
    'swap_ports' does the same thing as the above two swap functions but operates on the UDP source/destination ports.
*/
static __always_inline void swap_ports(struct context *ctx)
{
    __be16 temp;
    __builtin_memcpy(&temp, &ctx->udp->dest, sizeof(temp));
    __builtin_memcpy(&ctx->udp->dest, &ctx->udp->source, sizeof(temp));
    __builtin_memcpy(&ctx->udp->source, &temp, sizeof(temp));
}

SEC("tcbit")
int tcbit_fn(struct xdp_md *xdp_ctx)
{
    struct context ctx = to_ctx(xdp_ctx);

    /*
        So we need to parse out the packets we are receiving so that we only operate on UDP packets that are DNS.

        These functions are very similar to what we used in the xdpfw section and we will not be diving into these again here.
    */
    int action = parse_eth(&ctx);
    if (action != XDP_CONTINUE)
    {
        goto ret;
    }

    switch (ctx.nh_proto)
    {
    case ETH_P_IP:
        action = parse_v4(&ctx);
        break;
    case ETH_P_IPV6:
        action = parse_v6(&ctx);
        break;
    default:
        action = XDP_PASS;
    }

    if (action != XDP_CONTINUE)
    {
        goto ret;
    }

    switch (ctx.nh_proto)
    {
    case IPPROTO_UDP:
        action = parse_udp(&ctx);
        break;
    default:
        action = XDP_PASS;
    }

    if (action != XDP_CONTINUE)
    {
        goto ret;
    }

    /*
        So due to the above parsing we know that this packet is a UDP packet destined for port 53 on this host, and we can assume at least for the purposes
        of this workshop that its a DNS packet. In reality we would want to do more checks to ensure its a valid DNS packet in a real DDoS situation but for
        the sake of brevity those checks are assumed.
    */

    /*
        So just like the other headers we have been working with we take the start of the packet and add the offset we got from the last parser we ran.
    */
    ctx.dns = ctx.data_start + ctx.nh_offset;

    /*
        As always we need to confirm that we have enough space to work with the DNS packet data.
    */
    if (ctx.dns + 1 > ctx.data_end)
    {
        action = XDP_PASS;
        goto ret;
    }

    /*
        Since we will be updating the data contained in the packet we need to take a snapshot of the old data first so that we can compute the UDP checksum
        difference.
    */
    __u16 old_flags = ctx.dns->flags.data;

    /*
        Set the various DNS flags that we need to set to properly format a TC bit response to a DNS query, in this case:
            - set the qr bit to 1 which means its a query response.
            - set the opcode to 0 if its not already set to 0 meaning that this packet is a standard response.
            - set the aa bit to 0 since we are not responding authoritatively to this query.
            - set the tc bit to 1 since we are saying that this response is truncated and the client should retry over tcp.
            - set the ra bit to 1 since we are likely running on a server hosting a recurisve resolver. 
                (you would set this to 0 if you were operating on an authoritative dns server)
    */
    ctx.dns->flags.bits.qr = 1;
    ctx.dns->flags.bits.opcode = 0;
    ctx.dns->flags.bits.aa = 0;
    ctx.dns->flags.bits.tc = 1;
    ctx.dns->flags.bits.ra = 1;

    /*
        Update the UDP checksum due to the changes that we made to the dns flags.
    */
    csum_update(&ctx.udp->check, old_flags, ctx.dns->flags.data);

    /*
        Swap the various addresses so that the packet goes back to the client that sent the query originally.
    */
    swap_mac(&ctx);
    swap_ip(&ctx);
    swap_ports(&ctx);

    /*
        Set the action to XDP_TX telling the kernel to send this packet back out the same interface that it came in on.
    */
    action = XDP_TX;
ret:
    return update_action_stats(ctx.length, action);
}

char _license[] SEC("license") = "GPL";
