// SPDX-License-Identifier: GPL-2.0

#ifndef _XDP_PROG_HELPERS_H
#define _XDP_PROG_HELPERS_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <linux/if_link.h>
#include <stdbool.h>
#include <string.h>

#include "consts.h"

static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

static int detach(int if_index, char *prog_path)
{

    struct bpf_object *bpf_obj;
    int bpf_prog_fd = -1;
    int ret = 0;

    ret = bpf_prog_load(prog_path, BPF_PROG_TYPE_XDP, &bpf_obj, &bpf_prog_fd);
    if (ret != 0)
    {
        printf("ERR: Unable to load XDP program from file '%s' err(%d): %s\n",
               prog_path, -ret, strerror(-ret));
        return EXIT_FAIL_XDP_DETACH;
    }

    ret = bpf_set_link_xdp_fd(if_index, -1, 0);
    if (ret != 0)
    {
        printf("WARN: Cannont detach XDP program from specified device at index '%d' err(%d): %s\n",
               if_index, -ret, strerror(-ret));
    }

    ret = bpf_object__unpin_maps(bpf_obj, MAP_DIR);
    if (ret != 0)
    {
        printf("WARN: Unable to unpin the XDP program's '%s' maps from '%s' err(%d): %s\n",
               prog_path, MAP_DIR, -ret, strerror(-ret));
    }

    return EXIT_OK;
}

static int load_section(struct bpf_object *bpf_obj, char *section)
{
    struct bpf_program *bpf_prog;

    bpf_prog = bpf_object__find_program_by_title(bpf_obj, section);
    if (bpf_prog == NULL)
    {
        return -EINVAL;
    }

    return bpf_program__fd(bpf_prog);
}

static int attach(int if_index, char *prog_path, char *section)
{
    struct bpf_object *bpf_obj;
    int bpf_prog_fd = -1;
    int ret = 0;

    ret = bpf_prog_load(prog_path, BPF_PROG_TYPE_XDP, &bpf_obj, &bpf_prog_fd);
    if (ret != 0)
    {
        printf("ERR: Unable to load XDP program from file '%s' err(%d): %s\n",
               prog_path, -ret, strerror(-ret));
        return EXIT_FAIL_XDP_ATTACH;
    }

    int section_fd = load_section(bpf_obj, section);
    if (section_fd < 0)
    {
        printf("WARN: Unable to load section '%s' from load bpf object file '%s' err(%d): %s.\n",
               section, prog_path, -section_fd, strerror(-section_fd));
        printf("WARN: Falling back to first program in loaded bpf object file '%s'.\n",
               prog_path);
    }
    else
    {
        bpf_prog_fd = section_fd;
    }

    ret = bpf_set_link_xdp_fd(if_index, bpf_prog_fd, xdp_flags);
    if (ret != 0)
    {
        printf("ERR: Unable to attach loaded XDP program to specified device index '%d' err(%d): %s\n",
               if_index, -ret, strerror(-ret));
        return EXIT_FAIL_XDP_ATTACH;
    }

    ret = bpf_object__pin_maps(bpf_obj, MAP_DIR);
    if (ret != 0)
    {
        printf("ERR: Unable to pin the loaded and attached XDP program's maps to '%s' err(%d): %s\n",
               MAP_DIR, -ret, strerror(-ret));
        return EXIT_FAIL_XDP_MAP_PIN;
    }

    return EXIT_OK;
}

#endif // _XDP_PROG_HELPERS_H