// SPDX-License-Identifier: GPL-2.0

#include "pinning_user.h"

/*
    'handle_action' is the first time we will be using libbpf to update a BPF map from user space,
    so that the underlying XDP program can use this data to change how it responds to packets.
*/
static int handle_action(const char *str_action)
{
    /*
        Since we are passing in a string from the invocation of this program, we need to change it into the integer
        equivalent.
    */
    int action = str2action(str_action);
    if (action < 0)
    {
        printf("ERR: Failed to parse the suppled action '%s': must be one of "
               "['XDP_ABORTED', 'XDP_DROP', 'XDP_PASS', 'XDP_TX', 'XDP_REDIRECT'].\n",
               str_action);
        return EXIT_FAIL_OPTIONS;
    }

    /*
        Once we have the correct form of the action we want to use for all packets we need a file descriptor,
        to the BPF map in question, this is very similar to what we did in the last section. In fact this 'open_bpf_map'
        function is the same one just in located in 'common/headers/user_helpers.h' at the root of this repo.
    */
    int map_fd = open_bpf_map(ACTION_MAP_PATH);
    if (map_fd < 0)
    {
        return EXIT_FAIL_XDP_MAP_OPEN;
    }

    /*
        We have a single key/value stored in the map so the index that we are going to be updating in this
        map is always '0'.
    */
    __u32 action_idx = 0;

    /*
        We call 'bpf_map_update_elem' which from userspace takes the file descriptor to the BPF map we are updating,
        a pointer the to the key we are updating, and a pointer to the value we want to set the key to.

        If the key doesn't exist, or the file descriptor is not for the correct map then this runtion will return a non '0' error
        code and set errno.
    */
    if (bpf_map_update_elem(map_fd, &action_idx, &action, 0) != 0)
    {
        printf("ERR: Failed to set specified action '%s' err(%d): %s\n",
               str_action, errno, strerror(errno));
        return EXIT_FAIL_XDP_MAP_UPDATE;
    }
    return EXIT_OK;
}

/*
    'detach' is the first time we will be using libbpf to remove an XDP program from a given network interface.

    This replaces the process we ran through last time with iproute2 and rm to detach the program and unpin its maps.
*/
static int detach(int if_index, char *prog_path)
{
    /*
        We need some storage objects for the resulting bpf object file and the file descriptor to the program contained
        within the object.
    */
    struct bpf_object *bpf_obj;
    int bpf_prog_fd = -1;

    /*
        The following two calls 'bpf_prog_load' and 'bpf_set_link_xdp_fd' are the equivalent in libbpf as running:
            'sudo ip link set dev ${device name} xdp off'
    */

    /*
        'bpf_prog_load' handles loading a BPF program from disk based on the file path provided as the first argument.
        Its second argument is the type of BPF program to expect, in this case we are loading an XDP program. The final two
        arguments are a pointer to the bpf object storage and file descriptor above so we can interact with them on a succesful
        load.

        This will return a non-0 error code in the event something goes wrong.
    */
    if (bpf_prog_load(prog_path, BPF_PROG_TYPE_XDP, &bpf_obj, &bpf_prog_fd) != 0)
    {
        printf("ERR: Unable to load XDP program from file '%s' err(%d): %s\n",
               prog_path, errno, strerror(errno));
        return EXIT_FAIL_XDP_DETACH;
    }

    /*
        'bpf_set_link_xdp_fd' is where the actuall detach magic happens, and it takes the interface index that is supplied,
        and '-1' as the second argument which signals to the kernel that there should be no XDP program attached to said index.
    */
    if (bpf_set_link_xdp_fd(if_index, -1, 0) != 0)
    {
        printf("WARN: Cannont detach XDP program from specified device at index '%d' err(%d): %s\n",
               if_index, errno, strerror(errno));
    }

    /*
        'bpf_object__unpin_maps' handles removing all map references that exist in the bpf object we loaded previously from the '/sys/fs/bpf' filesystem.

        This is the equivalent to running:
            'sudo rm -f /sys/fs/bpf/${map name}'
    */
    if (bpf_object__unpin_maps(bpf_obj, MAP_DIR) != 0)
    {
        printf("WARN: Unable to unpin the XDP program's '%s' maps from '%s' err(%d): %s\n",
               prog_path, MAP_DIR, errno, strerror(errno));
    }

    return EXIT_OK;
}

/*
    'attach' is the first time we will be using libbpf to attach an XDP program to a given network interface.

    This replaces the process we ran through last time with iproute2 and bpftool to attach the program and pin its maps.
*/
static int attach(int if_index, char *prog_path)
{
    /*
        We need some storage objects for the resulting bpf object file and the file descriptor to the program contained
        within the object.
    */
    struct bpf_object *bpf_obj;
    int bpf_prog_fd = -1;

    /*
        The following two calls 'bpf_prog_load' and 'bpf_set_link_xdp_fd' are the equivalent in libbpf as running:
            'sudo ip link set dev ${device name} xdp obj ${object file} sec ${section name}'
    */

    /*
        'bpf_prog_load' handles loading a BPF program from disk based on the file path provided as the first argument.
        Its second argument is the type of BPF program to expect, in this case we are loading an XDP program. The final two
        arguments are a pointer to the bpf object storage and file descriptor above so we can interact with them on a succesful
        load.

        This will return a non-0 error code in the event something goes wrong.
    */
    if (bpf_prog_load(prog_path, BPF_PROG_TYPE_XDP, &bpf_obj, &bpf_prog_fd) != 0)
    {
        printf("ERR: Unable to load XDP program from file '%s' err(%d): %s\n",
               prog_path, errno, strerror(errno));
        return EXIT_FAIL_XDP_ATTACH;
    }

    /*
        'bpf_set_link_xdp_fd' is where the actuall attach magic happens, and it takes the interface index that is supplied,
        and the bpf progarm file descriptor we got in the last call as the second argument which signals to the kernel that
        we want the specified XDP program attached to said index.
    */
    if (bpf_set_link_xdp_fd(if_index, bpf_prog_fd, 0) != 0)
    {
        printf("ERR: Unable to attach loaded XDP program to specified device index '%d' err(%d): %s\n",
               if_index, errno, strerror(errno));
        return EXIT_FAIL_XDP_ATTACH;
    }

    /*
        'bpf_object__pin_maps' handles pinning all map references that exist in the bpf object we loaded previously to the '/sys/fs/bpf' filesystem.

        This is the equivalent to running:
            'sudo bpftool map list'
            'sudo bpftool map pin id ${map id} /sys/fs/bpf/${map name}'
    */
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
