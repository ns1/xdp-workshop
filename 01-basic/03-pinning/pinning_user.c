/* SPDX-License-Identifier: GPL-2.0 */

#include "pinning_user.h"

static int handle_action(const char *str_action)
{
    int action = str2action(str_action);
    if (action < 0)
    {
        printf("ERR: Failed to parse the suppled action '%s': must be one of "
               "['XDP_ABORTED', 'XDP_DROP', 'XDP_PASS', 'XDP_TX', 'XDP_REDIRECT'].\n",
               str_action);
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
               str_action, errno, strerror(errno));
        return EXIT_FAIL_XDP_MAP_UPDATE;
    }
    return EXIT_OK;
}

static int detach(int if_index, char *prog_path)
{

    struct bpf_object *bpf_obj;
    int bpf_prog_fd = -1;

    if (bpf_prog_load(prog_path, BPF_PROG_TYPE_XDP, &bpf_obj, &bpf_prog_fd) != 0)
    {
        printf("ERR: Unable to load XDP program from file '%s' err(%d): %s\n",
               prog_path, errno, strerror(errno));
        return EXIT_FAIL_XDP_DETACH;
    }

    if (bpf_set_link_xdp_fd(if_index, -1, 0) != 0)
    {
        printf("WARN: Cannont detach XDP program from specified device at index '%d' err(%d): %s\n",
               if_index, errno, strerror(errno));
    }

    if (bpf_object__unpin_maps(bpf_obj, MAP_DIR) != 0)
    {
        printf("WARN: Unable to unpin the XDP program's '%s' maps from '%s' err(%d): %s\n",
               prog_path, MAP_DIR, errno, strerror(errno));
    }

    return EXIT_OK;
}

static int attach(int if_index, char *prog_path)
{
    struct bpf_object *bpf_obj;
    int bpf_prog_fd = -1;

    if (bpf_prog_load(prog_path, BPF_PROG_TYPE_XDP, &bpf_obj, &bpf_prog_fd) != 0)
    {
        printf("ERR: Unable to load XDP program from file '%s' err(%d): %s\n",
               prog_path, errno, strerror(errno));
        return EXIT_FAIL_XDP_ATTACH;
    }

    if (bpf_set_link_xdp_fd(if_index, bpf_prog_fd, 0) != 0)
    {
        printf("ERR: Unable to attach loaded XDP program to specified device index '%d' err(%d): %s\n",
               if_index, errno, strerror(errno));
        return EXIT_FAIL_XDP_ATTACH;
    }

    if (bpf_object__pin_maps(bpf_obj, MAP_DIR) != 0)
    {
        printf("ERR: Unable to pin the loaded and attached XDP program's maps to '%s' err(%d): %s\n",
               MAP_DIR, errno, strerror(errno));
        return EXIT_FAIL_XDP_MAP_PIN;
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

    char *action = NULL;

    int rlimit_ret = set_rlimit();
    if (rlimit_ret != EXIT_OK)
    {
        return rlimit_ret;
    }

    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "hx::a:d:se:", long_options, &longindex)) != -1)
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
            return print_action_stats();
        case 'e':
            action = alloca(strlen(tmp_value));
            strcpy(action, tmp_value);
            break;
        case 'h':
        default:
            usage(argv, doc, long_options, long_options_descriptions);
            return EXIT_FAIL_OPTIONS;
        }
    }

    if (should_detach)
    {
        return detach(if_index, prog_path == NULL ? default_prog_path : prog_path);
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
