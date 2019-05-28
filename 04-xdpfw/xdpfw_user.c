// SPDX-License-Identifier: GPL-2.0

#include "xdpfw_user.h"

/*
    This application uses the same logic for attaching/detaching XDP programs as the last section, its just
    been moved into the common/headers/xdp_prog_helpers.h file in the root of this repo.
*/

/*
    'update_map' handles actually inserting or removing a given key from the given map. This is done by leveraging
    libbpf's 'bpf_map_update_elem' and 'bpf_map_delete_elem'.
*/
static int update_map(const char *map, void *key, bool insert)
{
    /*
        Before we can update/delete elements from our blacklists. We need to grab the file descriptor to the
        BPF map in question just like we did in the previous section.
    */
    int map_fd = open_bpf_map(map);
    if (map_fd < 0)
    {
        return EXIT_FAIL_XDP_MAP_OPEN;
    }

    /*
        Because we want this application to be able to add and remove entries for our blacklist maps we need to leverage both
        'bpf_map_update_elem' and 'bpf_map_delete_elem'. The former is the same as we did in the last section. However the latter
        is a new function entirely.
    */

    if (insert)
    {
        /*
            Just like in the last section we pass in the file descriptor for our map and then the key, which in this case is the
            supplied key after parsing and a value of 0. We don't care about the value in this case, just that it exists
            in the map.
        */
        __u8 value = 0;
        if (bpf_map_update_elem(map_fd, key, &value, BPF_NOEXIST) != 0)
        {
            return EXIT_FAIL_XDP_MAP_UPDATE;
        }
    }
    else
    {
        /*
            In order to remove a element from a given map we follow a similar procedure as the above update call however we use the
            function 'bpf_map_delete_elem' which takes the file descriptor to the map we wish to delete the element from, and the key
            we want to remove.

            This will return a non-0 error code in the event it fails just like 'bpf_map_update_elem' above.
        */
        if (bpf_map_delete_elem(map_fd, key) != 0)
        {
            return EXIT_FAIL_XDP_MAP_UPDATE;
        }
    }

    return EXIT_OK;
}

/*
    'handle_mac' handles either adding or removing a given MAC address from the 'mac_blacklist' BPF map, and will
    be the first time we leverage the libbpf function 'bpf_map_delete_elem'.
*/
static int handle_mac(char *mac_addr, bool insert)
{
    /*
        First since we are passed in a string representation of a MAC address, in the form '00:00:00:00:00:00' we need
        to convert it into the proper form. We are going to 'sscanf' for this which while valid is likely not the best
        or most performant way to go about this. However it is more than enough for this workshop.
    */
    unsigned char mac[6];
    if (6 != sscanf(mac_addr, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]))
    {
        printf("ERR: Invalid MAC address specifed must be in the form '00:00:00:00:00:00', got '%s",
               mac_addr);
        return EXIT_FAIL_OPTIONS;
    }

    /*
        Lets let the user know what we are doing.
    */
    printf("%s source MAC address '%s'.\n", insert ? "Blacklisting" : "Whitelisting", mac_addr);

    /*
        We then call update_map which handles opening the specified map and inserting or removing the given key.

        This will return a non-0 error code on a failure, and leaves errno set to the underlying error.
    */
    int ret = update_map(MAC_BLACKLIST_PATH, &mac, insert);
    if (ret != 0)
    {
        printf("ERR: Failed to %s specified MAC address '%s' err(%d): %s\n",
               insert ? "blacklist" : "whitelist", mac_addr, errno, strerror(errno));
    }
    return ret;
}

/*
    'handle_prefix' handles either adding or removing a given IP prefix for either IPv4 or IPv6 from the respective
    'v4_blacklist' or 'v6_blacklist' BPF maps. It does so in the same way as the 'handle_mac' function above.
*/
static int handle_prefix(char *prefix, bool insert, bool v4)
{
    /*
        Like in 'handle_mac' we are given a string representation of the IP prefix we want to drop so we need to parse it
        into the correct form for use as a key.

        Note that we aren't using our custom 'lpm_v4_key' and 'lpm_v6_key' structs here, so that we can handle both IPv4 and
        IPv6 with a single key type. This is thanks to us being able to use alloca or really any allocation routine in order to
        kill out the 'bpf_lpm_trie_key' arbitrary data size. We can't do this in XDP because of the restriction against allocating
        HEAP memory, i.e. calling any kind of allocation routine.
    */
    struct bpf_lpm_trie_key *key = alloca(v4 ? sizeof(struct lpm_v4_key) : sizeof(struct lpm_v6_key));

    /*
        Since we are passed in a string representation of an IP address prefix, in the form '0.0.0.0/0' or '::/0' we need
        to convert it into the proper form. We are going to 'sscanf' for this which while valid is likely not the best
        or most performant way to go about this. However it is more than enough for this workshop.
    */
    int addr_len = v4 ? INET_ADDRSTRLEN : INET6_ADDRSTRLEN;
    char *addr = alloca(addr_len);
    if (2 != sscanf(prefix, "%[^/]%*c%d", addr, &key->prefixlen))
    {
        printf("ERR: Invalid IP address prefix specifed must be in the form '1.1.1.1/32' or '::1/128', got '%s'.\n",
               prefix);
        return EXIT_FAIL_OPTIONS;
    }

    /*
        The IP address segment takes a bit of extra processing to ensure its in the right form so we call 'inet_pton' which will parse
        the string form of the IP into the correct IP address format for either IPv4 or IPv6
    */
    if (inet_pton(v4 ? AF_INET : AF_INET6, addr, key->data) != 1)
    {
        printf("ERR: Invalid IP address specified as part of the supplied prefix '%s'\n",
               prefix);
        return EXIT_FAIL_OPTIONS;
    }

    /*
        Lets let the user know what we are doing.
    */
    printf("%s source IP%s prefix '%s'.\n", insert ? "Blacklisting" : "Whitelisting", v4 ? "v4" : "v6", prefix);

    /*
        We then call update_map which handles opening the specified map and inserting or removing the given key.

        This will return a non-0 error code on a failure, and leaves errno set to the underlying error.
    */
    int ret = update_map(v4 ? V4_BLACKLIST_PATH : V6_BLACKLIST_PATH, key, insert);
    if (ret != 0)
    {
        printf("ERR: Failed to %s specified IP address prefix '%s' err(%d): %s\n",
               insert ? "blacklist" : "whitelist", prefix, errno, strerror(errno));
    }
    return ret;
}

/*
    'handle_port' handles either adding or removing a given port/protocol/type from the 'port_blacklist' BPF map.
    It does so in the same way as the 'handle_mac' and 'handle_prefix' functions above.
*/
static int handle_port(char *port, bool insert, bool udp, bool src)
{
    /*
        To handle our port blacklist we need to use our custom 'port_key' struct, this is used the same way here as it is in the XDP program,
        and we just set the various fields to their appropriate values based on the supplied arguments. To handle the port we are simply relying
        on 'atoi', which isn't the best as we will silently error on non-integer values passed in, but again for the purposes of this workshop
        its more than enough.
    */
    struct port_key *key = alloca(sizeof(struct port_key));

    key->type = src ? source_port : destination_port;
    key->proto = udp ? udp_port : tcp_port;
    key->port = atoi(port);

    /*
        Lets let the user know what we are doing.
    */
    printf("%s %s port '%s/%s'.\n", insert ? "Blacklisting" : "Whitelisting", src ? "source" : "dest", port, udp ? "udp" : "tcp");

    /*
        We then call update_map which handles opening the specified map and inserting or removing the given key.

        This will return a non-0 error code on a failure, and leaves errno set to the underlying error.
    */
    int ret = update_map(PORT_BLACKLIST_PATH, key, insert);
    if (ret != 0)
    {
        printf("ERR: Failed to %s specified %s port '%s/%s' err(%d): %s\n",
               insert ? "blacklist" : "whitelist", src ? "source" : "dest", port, udp ? "udp" : "tcp", errno, strerror(errno));
    }
    return ret;
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
    char *prefix_v4 = NULL;
    char *prefix_v6 = NULL;

    bool is_udp = true;

    char *dest_port = NULL;
    char *src_port = NULL;

    int rlimit_ret = set_rlimit();
    if (rlimit_ret != EXIT_OK)
    {
        return rlimit_ret;
    }

    while ((opt = getopt_long(argc, argv, "hx::n::a:d:sirm:4:6:t:c:p:", long_options, &longindex)) != -1)
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
        case '4':
            prefix_v4 = alloca(strlen(optarg));
            strcpy(prefix_v4, optarg);
            break;
        case '6':
            prefix_v6 = alloca(strlen(optarg));
            strcpy(prefix_v6, optarg);
            break;
        case 't':
            dest_port = alloca(strlen(optarg));
            strcpy(dest_port, optarg);
            break;
        case 'c':
            src_port = alloca(strlen(optarg));
            strcpy(src_port, optarg);
            break;
        case 'p':
            if (strcmp("udp", optarg) == 0)
            {
                is_udp = true;
                break;
            }
            if (strcmp("tcp", optarg) == 0)
            {
                is_udp = false;
                break;
            }
            printf("ERR: Invalid protocol specified with '-p|--proto' must be either "
                   "'udp' or 'tcp', got '%s'.",
                   optarg);
            return EXIT_FAIL_OPTIONS;
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

    if (prefix_v4 != NULL)
    {
        return handle_prefix(prefix_v4, insert, true);
    }
    if (prefix_v6 != NULL)
    {
        return handle_prefix(prefix_v6, insert, false);
    }

    if (dest_port != NULL)
    {
        return handle_port(dest_port, insert, is_udp, false);
    }
    if (src_port != NULL)
    {
        return handle_port(src_port, insert, is_udp, true);
    }

    return EXIT_OK;
}
