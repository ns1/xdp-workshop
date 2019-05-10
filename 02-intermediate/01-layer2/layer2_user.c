/* SPDX-License-Identifier: GPL-2.0 */

#include "layer2_user.h"

char *default_prog_path = "layer2_kern.o";

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

static int print_stats()
{
    int map_fd = open_bpf_map(COUNTER_MAP_PATH);
    if (map_fd < 0)
    {
        return EXIT_FAIL_XDP_MAP_OPEN;
    }
    return get_percpu_stats(map_fd);
}

static int handle_mac(char *mac_addr, bool insert)
{
    unsigned char mac[6];

    if (6 != sscanf(mac_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1],
                    &mac[2], &mac[3], &mac[4], &mac[5]))
    {
        printf("ERR: Invalid MAC address specifed must be in the form "
               "'00:00:00:00:00:00', got '%s",
               mac_addr);
        return EXIT_FAIL_OPTIONS;
    }

    int map_fd = open_bpf_map(MAC_BLACKLIST_PATH);
    if (map_fd < 0)
    {
        return EXIT_FAIL_XDP_MAP_OPEN;
    }

    if (insert)
    {
        __u8 value = 0;
        if (bpf_map_update_elem(map_fd, &mac, &value, BPF_NOEXIST) != 0)
        {
            printf(
                "ERR: Failed to blacklist specified MAC address '%s' err(%d): %s\n",
                mac_addr, errno, strerror(errno));
            return EXIT_FAIL_XDP_MAP_UPDATE;
        }
    }
    else
    {
        if (bpf_map_delete_elem(map_fd, &mac) != 0)
        {
            printf(
                "ERR: Failed to whitelist specified MAC address '%s' err(%d): %s\n",
                mac_addr, errno, strerror(errno));
            return EXIT_FAIL_XDP_MAP_UPDATE;
        }
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

    char *mac_addr = NULL;

    int rlimit_ret = set_rlimit();
    if (rlimit_ret != EXIT_OK)
    {
        return rlimit_ret;
    }

    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "hx::a:d:sirm:", long_options,
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
        case 'i':
            insert = true;
            break;
        case 'r':
            insert = false;
            break;
        case 'm':
            mac_addr = alloca(strlen(tmp_value));
            strcpy(mac_addr, tmp_value);
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

    if (mac_addr != NULL)
    {
        return handle_mac(mac_addr, insert);
    }

    return EXIT_OK;
}
