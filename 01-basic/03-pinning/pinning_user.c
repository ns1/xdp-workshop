/* SPDX-License-Identifier: GPL-2.0 */

#include "pinning_user.h"

char *default_prog_path = "pinning_kern.o";

int open_bpf_map(const char *file)
{
    int fd;

    fd = bpf_obj_get(file);
    if (fd < 0)
    {
        printf("ERR: Failed to open bpf map file: '%s' err(%d): %s\n", file, errno,
               strerror(errno));
        return -errno;
    }
    return fd;
}

static int get_percpu_stats(int fd)
{
    unsigned int num_cpus = bpf_num_possible_cpus();
    struct counters values[num_cpus];
    struct counters overall = {
        .bytes = 0,
        .packets = 0,
    };

    for (__u32 i = 0; i < XDP_MAX_ACTIONS; i++)
    {
        overall.bytes = 0;
        overall.packets = 0;

        if ((bpf_map_lookup_elem(fd, &i, values)) != 0)
        {
            printf("ERR: Failed to lookup map counter for action '%s' err(%d): %s\n",
                   action2str(i), errno, strerror(errno));
            return EXIT_FAIL_XDP_MAP_LOOKUP;
        }

        for (int j = 0; j < num_cpus; j++)
        {
            overall.bytes += values[j].bytes;
            overall.packets += values[j].packets;
        }
        printf("Action '%s':\nPackets: %llu\nBytes:   %llu Bytes\n\n",
               action2str(i), overall.packets, overall.bytes);
    }

    return EXIT_OK;
}

static int print_stats()
{
    int map_fd = open_bpf_map(COUNTER_MAP_PATH);
    if (map_fd < 0)
    {
        return EXIT_FAIL_XDP_MAP_OPEN;
    }
    return get_percpu_stats(map_fd);
}

static int handle_action(const char *str_action)
{
    int action = str2action(str_action);
    if (action < 0)
    {
        printf("ERR: Failed to parse the suppled action '%s': must be one of [",
               str_action);
        for (int i = 0; i < XDP_MAX_ACTIONS; i++)
        {
            printf("'%s'", xdp_action_names[i]);
            if (i != XDP_MAX_ACTIONS - 1)
            {
                printf(", ");
            }
        }
        printf("].\n");
        return EXIT_FAIL_OPTIONS;
    }

    int map_fd = open_bpf_map(ACTION_MAP_PATH);
    if (map_fd < 0)
    {
        return EXIT_FAIL_XDP_MAP_OPEN;
    }

    __u32 action_idx = 0;
    if (bpf_map_update_elem(map_fd, &action_idx, &action, 0) != 0)
    {
        printf("ERR: Failed to set specified action '%s' err(%d): %s\n",
               action2str(action), errno, strerror(errno));
        return EXIT_FAIL_XDP_MAP_UPDATE;
    }
    return EXIT_OK;
}

static int get_ifindex(const char *raw_ifname)
{
    char ifname_buf[IF_NAMESIZE];
    char *ifname = NULL;

    if (strlen(raw_ifname) >= IF_NAMESIZE)
    {
        printf("ERR: Device name '%s' too long: must be less than %d characters\n",
               raw_ifname, IF_NAMESIZE);
        return -1;
    }
    ifname = (char *)&ifname_buf;
    strncpy(ifname, raw_ifname, IF_NAMESIZE);

    int if_index = if_nametoindex(ifname);
    if (if_index == 0)
    {
        printf("ERR: Device name '%s' not found err(%d): %s\n", raw_ifname, errno,
               strerror(errno));
        return -1;
    }

    return if_index;
}

static int detach(int if_index)
{
    if (bpf_set_link_xdp_fd(if_index, -1, 0) != 0)
    {
        printf("WARN: Cannont detach XDP program from specified device at index "
               "'%d' err(%d): %s\n",
               if_index, errno, strerror(errno));
    }

    for (int i = 0; i < NUM_MAPS; i++)
    {
        if (unlink(xdp_maps[i]) < 0)
        {
            printf("WARN: cannot rm map file '%s' err(%d): %s\n", xdp_maps[i], errno,
                   strerror(errno));
        }
    }

    return EXIT_OK;
}

static int attach(int if_index, char *prog_path)
{
    struct bpf_object *bpf_obj;
    int bpf_prog_fd = -1;

    if (bpf_prog_load(prog_path, BPF_PROG_TYPE_XDP, &bpf_obj, &bpf_prog_fd) !=
        0)
    {
        printf("ERR: Unable to load XDP program from file '%s' err(%d): %s\n",
               prog_path, errno, strerror(errno));
        return EXIT_FAIL_XDP_DETACH;
    }

    if (bpf_set_link_xdp_fd(if_index, bpf_prog_fd, 0) != 0)
    {
        printf("ERR: Unable to attach loaded XDP program to specified device index "
               "'%d' err(%d): %s\n",
               if_index, errno, strerror(errno));
        return EXIT_FAIL_XDP_DETACH;
    }

    if (bpf_object__pin_maps(bpf_obj, MAP_DIR) != 0)
    {
        printf("ERR: Unable to pin the loaded and attached XDP program's maps to "
               "'%s' err(%d): %s\n",
               MAP_DIR, errno, strerror(errno));
        return EXIT_FAIL_XDP_MAP_PIN;
    }

    return EXIT_OK;
}

static int set_rlimit()
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};

    if (setrlimit(RLIMIT_MEMLOCK, &r))
    {
        printf("ERR: failed to call setrlimit(RLIMIT_MEMLOCK, RLIM_INFINITY) "
               "err(%d): %s\n",
               errno, strerror(errno));
        return EXIT_FAIL_RLIMIT;
    }
    return EXIT_OK;
}

int main(int argc, char **argv)
{
    int opt;
    int longindex = 0;

    char *prog_path = NULL;
    int if_index = -1;

    bool should_detach = false;
    bool should_attach = false;

    bool insert = true;

    char *action = NULL;

    int rlimit_ret = set_rlimit();
    if (rlimit_ret != EXIT_OK)
    {
        return rlimit_ret;
    }

    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "hx::a:d:se:", long_options,
                              &longindex)) != -1)
    {
        char *tmp_value = optarg;
        switch (opt)
        {
        case 'x':
            if (handle_optional_argument(argc, argv))
            {
                tmp_value = argv[optind++];
                prog_path = alloca(strlen(tmp_value));
                strcpy(prog_path, tmp_value);
            }
            break;
        case 'a':
            if (should_detach)
            {
                printf("ERR: Must not specify both '-a|--attach' and '-d|--detach' "
                       "during the same invocation.\n");
                return EXIT_FAIL_OPTIONS;
            }
            should_attach = true;
            if_index = get_ifindex(optarg);
            if (if_index < 0)
            {
                return EXIT_FAIL_OPTIONS;
            }
            break;
        case 'd':
            if (should_attach)
            {
                printf("ERR: Must not specify both '-a|--attach' and '-d|--detach' "
                       "during the same invocation.\n");
                return EXIT_FAIL_OPTIONS;
            }
            should_detach = true;
            if_index = get_ifindex(optarg);
            if (if_index < 0)
            {
                return EXIT_FAIL_OPTIONS;
            }
            break;
        case 's':
            return print_stats();
        case 'e':
            action = alloca(strlen(tmp_value));
            strcpy(action, tmp_value);
            break;
        case 'h':
        default:
            usage(argv);
            return EXIT_FAIL_OPTIONS;
        }
    }

    if (should_detach)
    {
        return detach(if_index);
    }

    if (should_attach)
    {
        return attach(if_index, prog_path == NULL ? default_prog_path : prog_path);
    }

    if (action != NULL)
    {
        return handle_action(action);
    }

    return EXIT_OK;
}
