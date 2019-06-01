/* SPDX-License-Identifier: GPL-2.0 */

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>

#include "kernel/bpf_util.h"

#include "common.h"

int open_bpf_map(const char *file)
{
    int fd;

    fd = bpf_obj_get(file);
    if (fd < 0)
    {
        printf("ERR: Failed to open bpf map file '%s' err(%d): %s\n",
               file, errno, strerror(errno));
        return -errno;
    }
    return fd;
}

/*
    ---------- SOLUTION ----------

    We need to update the original 'get_array_stats' for use with a PERCPU variant of the
    'BPF_MAP_TYPE_ARRAY' map object. Overall this function operates very similarlly to its original
    counterpart in terms of interface, however its largest deviation is that it will print the per-cpu
    metrics before returning the overall stats collected.
*/
static __u64 get_percpu_array_stats(int fd, struct counters *overall)
{
    /*
        We need to get the total number of CPU's that are running our XDP application, and then use
        this information to create an array of our 'struct counters' objects.

        The array will be used the same was as the original 'get_array_stats' used the passed in 'struct counters'
        pointer. The array gets passed as the value for 'bpf_map_lookup_elem' and the kernel handles filling in the
        various indexes.
    */
    unsigned int num_cpus = bpf_num_possible_cpus();
    struct counters cnts[num_cpus];
    __u32 counter_idx = 0;

    /*
        Because 'cnts' is an array we don't need to pass it as a pointer i.e. as '&cnts' which would actually be a pointer to a
        pointer in this case.
    */
    if (bpf_map_lookup_elem(fd, &counter_idx, cnts) != 0)
    {
        printf("ERR: Failed to open bpf map object fd '%d' err(%d): %s\n",
               fd, errno, strerror(errno));
        return -1;
    }

    /*
        Since we have multiple values to handle, we need to loop over them and sum and print the values for each index in the array,
        which represent a single CPU's statistics.
    */
    int i;
    for (i = 0; i < num_cpus; i++)
    {
        printf("CPU: %d\n", i);
        printf("\tPackets: %llu\n", cnts[i].packets);
        printf("\tBytes:   %llu Bytes\n", cnts[i].bytes);

        overall->packets += cnts[i].packets;
        overall->bytes += cnts[i].bytes;
    }

    return 0;
}
/*
    -------- END SOLUTION --------
*/

int main(int argc, char **argv)
{
    int fd = open_bpf_map("/sys/fs/bpf/counters");
    if (fd < 0)
    {
        return 1;
    }

    struct counters overall = {
        .packets = 0,
        .bytes = 0,
    };
    if (get_percpu_array_stats(fd, &overall) < 0)
    {
        return 1;
    }

    printf("Overall:\n");
    printf("\tPackets: %llu\n", overall.packets);
    printf("\tBytes:   %llu Bytes\n", overall.bytes);
    return 0;
}
