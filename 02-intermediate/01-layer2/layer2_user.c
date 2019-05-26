/* SPDX-License-Identifier: GPL-2.0 */

#include "layer2_user.h"

static int handle_mac(char *mac_addr, bool insert)
{
    unsigned char mac[6];

    if (6 != sscanf(mac_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
                    &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]))
    {
        printf("ERR: Invalid MAC address specifed must be in the form "
               "'00:00:00:00:00:00', got '%s'.",
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
            printf("ERR: Failed to blacklist specified MAC address '%s' err(%d): %s\n",
                   mac_addr, errno, strerror(errno));
            return EXIT_FAIL_XDP_MAP_UPDATE;
        }
    }
    else
    {
        if (bpf_map_delete_elem(map_fd, &mac) != 0)
        {
            printf("ERR: Failed to whitelist specified MAC address '%s' err(%d): %s\n",
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
    char *section = NULL;

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

    libbpf_set_print(NULL);

    /* Parse commands line args */
    while ((opt = getopt_long(argc, argv, "hx::n::a:d:sirm:", long_options, &longindex)) != -1)
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
        case 'n':
            if (handle_optional_argument(argc, argv))
            {
                tmp_value = argv[optind++];
                section = alloca(strlen(tmp_value));
                strcpy(section, tmp_value);
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
        return attach(if_index, prog_path == NULL ? default_prog_path : prog_path, section == NULL ? default_section : section);
    }

    if (mac_addr != NULL)
    {
        return handle_mac(mac_addr, insert);
    }

    return EXIT_OK;
}
