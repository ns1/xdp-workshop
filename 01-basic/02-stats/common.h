#ifndef _STATS_COMMON_H
#define _STATS_COMMON_H

#include <linux/types.h>

/* The counters struct bellow represents the number of packets and bytes a given
 * XDP program has encountered.
 *
 * Notice that there is no distinction between RX and TX since XDP programs only
 * see RX and have no ability to interact with, packets transmitted from the
 * host.
 */
struct counters {
  __u64 packets;
  __u64 bytes;
};

#endif /* _STATS_COMMON_H */
