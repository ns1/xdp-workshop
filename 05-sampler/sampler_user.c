// SPDX-License-Identifier: GPL-2.0

#include "sampler_user.h"

bool run = true;

int if_index = -1;
char *prog_path = NULL;
char *section = NULL;

static int perf_event_fds[MAX_CPUS];
static struct perf_event_mmap_page *perf_event_mmaps[MAX_CPUS];

static int page_size;
static int page_count = 8;

static void signal_handler(int sig)
{
    if (run)
    {
        detach(if_index, prog_path == NULL ? default_prog_path : prog_path);
        run = false;
    }
}

static int handle_rate(char *rate_str)
{
    __u32 key = 0;
    __u32 rate = atoi(rate_str);

    int map_fd = open_bpf_map(SAMPLE_RATE_PATH);
    if (map_fd < 0)
    {
        return EXIT_FAIL_XDP_MAP_OPEN;
    }

    if (bpf_map_update_elem(map_fd, &key, &rate, 0) != 0)
    {
        printf("ERR: Failed to update sample rate to %d err(%d): %s\n",
               rate, errno, strerror(errno));
        return EXIT_FAIL_XDP_MAP_UPDATE;
    }
    return EXIT_OK;
}

static int print_event(void *data, int size, int *cpu)
{
    struct perf_metadata *metadata = data;

    if (metadata->cookie != 0xcafe)
    {
        printf("ERR: Invalid cookie recieved from kernel got %x expected 0xcafe", metadata->cookie);
        return LIBBPF_PERF_EVENT_ERROR;
    }

    printf("Packet Captured (cpu: %d) (len: %d)\n", *cpu, metadata->length);
    return LIBBPF_PERF_EVENT_CONT;
}

static enum bpf_perf_event_ret bpf_perf_event_print(struct perf_event_header *hdr, void *private_data)
{
    struct perf_event_sample *e = (struct perf_event_sample *)hdr;
    int ret;

    if (e->header.type == PERF_RECORD_SAMPLE)
    {
        int *cpu = private_data;
        ret = print_event(e->data, e->size, cpu);
        if (ret != LIBBPF_PERF_EVENT_CONT)
            return ret;
    }
    else if (e->header.type == PERF_RECORD_LOST)
    {
        struct
        {
            struct perf_event_header header;
            __u64 id;
            __u64 lost;
        } *lost = (void *)e;
        printf("lost %lld events\n", lost->lost);
    }
    else
    {
        printf("unknown event type=%d size=%d\n",
               e->header.type, e->header.size);
    }

    return LIBBPF_PERF_EVENT_CONT;
}

static inline int syscall_perf_event_open(struct perf_event_attr *attr, int cpu)
{
    int fd = syscall(SYS_perf_event_open, attr, -1, cpu, -1, 0);
    return fd;
}

int poll_events(int num_cpus)
{
    struct pollfd *poller_fds;
    void *buf = NULL;
    size_t len = 0;
    int i;

    poller_fds = calloc(num_cpus, sizeof(*poller_fds));
    if (!poller_fds)
    {
        return LIBBPF_PERF_EVENT_ERROR;
    }

    for (i = 0; i < num_cpus; i++)
    {
        poller_fds[i].fd = perf_event_fds[i];
        poller_fds[i].events = POLLIN;
    }

    while (run)
    {
        poll(poller_fds, num_cpus, 1000);
        for (i = 0; i < num_cpus; i++)
        {
            if (!poller_fds[i].revents)
                continue;

            enum bpf_perf_event_ret ret = bpf_perf_event_read_simple(perf_event_mmaps[i],
                                                                     page_count * page_size,
                                                                     page_size, &buf, &len,
                                                                     bpf_perf_event_print,
                                                                     &i);
            if (ret != LIBBPF_PERF_EVENT_CONT)
                break;
        }
    }

    free(buf);
    free(poller_fds);

    return EXIT_OK;
}

static int setup_event_watchers(int map_fd, int num_cpus)
{
    int mmap_size;

    page_size = getpagesize();
    mmap_size = page_size * (page_count + 1);

    struct perf_event_attr attr = {
        .sample_type = PERF_SAMPLE_RAW,
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_BPF_OUTPUT,
        .wakeup_events = 1,
    };

    for (int i = 0; i < num_cpus; i++)
    {
        perf_event_fds[i] = syscall_perf_event_open(&attr, i);
        if (perf_event_fds[i] < 0)
        {
            printf("ERR: Failed to open perf event fd for cpu %d err(%d): %s\n",
                   i, errno, strerror(errno));
            return EXIT_FAIL_GENERIC;
        }

        if (bpf_map_update_elem(map_fd, &i, &perf_event_fds[i], 0) != 0)
        {
            printf("ERR: Failed to update perf event map for cpu %d with fd %d err(%d): %s\n",
                   i, perf_event_fds[i], errno, strerror(errno));
            return EXIT_FAIL_XDP_MAP_UPDATE;
        }

        ioctl(perf_event_fds[i], PERF_EVENT_IOC_ENABLE, 0);

        void *base = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, perf_event_fds[i], 0);
        if (base == MAP_FAILED)
        {
            printf("ERR: Failed to allocate mmaped buffer for cpu %d and fd %d err(%d): %s\n",
                   i, perf_event_fds[i], errno, strerror(errno));
            return EXIT_FAIL_GENERIC;
        }

        perf_event_mmaps[i] = base;
    }

    return EXIT_OK;
}

int main(int argc, char **argv)
{
    int opt;
    int longindex = 0;

    char *rate = NULL;

    int rlimit_ret = set_rlimit();
    if (rlimit_ret != EXIT_OK)
    {
        return rlimit_ret;
    }

    while ((opt = getopt_long(argc, argv, "hx::n::i:sr:", long_options, &longindex)) != -1)
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
        case 'i':
            if_index = get_ifindex(optarg);
            if (if_index < 0)
            {
                return EXIT_FAIL_OPTIONS;
            }
            break;
        case 's':
            return print_action_stats();
        case 'r':
            rate = alloca(strlen(optarg));
            strcpy(rate, optarg);
            return handle_rate(rate);
        case 'h':
        default:
            usage(argv, doc, long_options, long_options_descriptions);
            return EXIT_FAIL_OPTIONS;
        }
    }

    int ret = attach(if_index, prog_path == NULL ? default_prog_path : prog_path, section == NULL ? default_section : section);
    if (ret != 0)
    {
        return ret;
    }

    signal(SIGINT, signal_handler);
    signal(SIGHUP, signal_handler);
    signal(SIGTERM, signal_handler);

    int map_fd = open_bpf_map(SAMPLES_PATH);
    if (map_fd < 0)
    {
        kill(0, SIGINT);
        return EXIT_FAIL_XDP_MAP_OPEN;
    }

    int num_cpus = bpf_num_possible_cpus();

    ret = setup_event_watchers(map_fd, num_cpus);
    if (ret != 0)
    {
        kill(0, SIGINT);
        return ret;
    }

    ret = poll_events(num_cpus);
    kill(0, SIGINT);
    return ret;
}