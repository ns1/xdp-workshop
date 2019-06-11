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

/*
    'handle_rate' is very similar to the various update calls we were looking at in the last section of the workshop, and this
    one just handles passing in the specified rate to the MAP so that we can augment how many packets are sampled at any given point.
*/
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

/*
    'perf_event' handles actually parsing a valid perf event received from the XDP program.
*/
static int print_event(void *data, int size, int *cpu)
{
    /*
        So first we convert the data to our custom 'perf_metadata' struct but in this case its actually slightly different than the
        kernel space variant of this same struct, and it includes a 'data' field that will actually contain the packet data for this sample.
    */
    struct perf_metadata *metadata = data;

    /*
        Once we have our data lets make sure that the cookie we set in the XDP program is valid and correct.
    */
    if (metadata->cookie != 0xcafe)
    {
        printf("ERR: Invalid cookie recieved from kernel got %x expected 0xcafe", metadata->cookie);
        return LIBBPF_PERF_EVENT_ERROR;
    }

    /*
        For sake of brevity lets just print out which CPU received this event and the length of data receieved.
    */
    printf("Packet Captured (cpu: %d) (len: %d)\n", *cpu, metadata->length);
    return LIBBPF_PERF_EVENT_CONT;
}

/*
    'bpf_perf_event_print' handles parsing individual perf events that we recieve from the XDP programs, and is used as a hook to the call to 
    'bpf_perf_event_read_simple' leveraged in the 'poll_events' function bellow.
*/
static enum bpf_perf_event_ret bpf_perf_event_print(struct perf_event_header *hdr, void *private_data)
{
    /*
        First we need to convert the supplied 'perf_event_header' to a 'perf_event_sample. So that we can determine what type of event this is and act
        accordingly based on that information.
    */
    struct perf_event_sample *e = (struct perf_event_sample *)hdr;
    int ret;

    /*
        if we find that the type of event is a PERF_RECORD_SAMPLE we know that this event is data for us to parse and print out.
    */
    if (e->header.type == PERF_RECORD_SAMPLE)
    {
        /*
            Since we are passing in the CPU id of this event as our private_data lets convert that to an int pointer so that we can leverage it in the 
            call to 'print_event'
        */
        int *cpu = private_data;

        /*
            Pass off the data, size, and cpu id to 'print_event'
        */
        ret = print_event(e->data, e->size, cpu);
        if (ret != LIBBPF_PERF_EVENT_CONT)
            return ret;
    }
    /*
        If we find that the type of event is a PERF_RECORD_LOST we know that something went wrong and we dropped events, there are a lot of reasons why
        a perf event might be lost including not having enough memory available for capturing the event.
    */
    else if (e->header.type == PERF_RECORD_LOST)
    {
        struct
        {
            struct perf_event_header header;
            __u64 id;
            __u64 lost;
        } *lost = (void *)e;

        int *cpu = private_data;
        printf("ERR: Lost %lld events since the last iteratione for CPU %d\n", lost->lost, *cpu);
    }
    /*
        If we have gotten here we have some unknown event type so log it and move on.
    */
    else
    {
        printf("ERR: Unknown event type %d with a size of %d\n",
               e->header.type, e->header.size);
    }

    return LIBBPF_PERF_EVENT_CONT;
}

/*
    'syscall_perf_event_open' is a wrapper around the raw syscall function for calling 'perf_event_open' which is what we need to call for each CPU we want to monitor events from.
*/
static inline int syscall_perf_event_open(struct perf_event_attr *attr, int cpu)
{
    /*
        This maps out to: syscall(ID, ATTR, PID, CPU, GROUP_ID, FLAGS);
        - ID: SYS_perf_event_open is the syscall ID for the function we wish to call.
        - ATTR: a struct perf_event_attr pointer is the struct we configure in 'setup_event_watchers'.
        - PID: is set to -1 in this case because we are ignoring pid filtering.
        - CPU: is set to the cpu for the associated file descriptor and is passed in from 'setup_event_watchers'.
        - GROUP_ID: is set to -1 in this case because we are ignoring the group filtering.
        - FLAGS: is set to 0 to leverage default behavior.
    */
    int fd = syscall(SYS_perf_event_open, attr, -1, cpu, -1, 0);
    return fd;
}

/*
    'poll_events' handles polling for perf events being emitted from our XDP program and leveraging a set of preconfigured file descriptors and mmap regions.

    In general this is a very standard poll configuration that you might find in any async application leveraging standard poll symantics. Once we receive events for
    a given file descriptor we hand off the the corresponding mmap region to the call 'bpf_perf_event_read_simple' which handles pulling the event off the mmap region and calling
    the passed in parser func for each event recieved.
*/
int poll_events(int num_cpus)
{
    /*
        We need a few storage variables to handle polling for each of our cpu's.
    */
    struct pollfd *poller_fds;
    void *buf = NULL;
    size_t len = 0;
    int i;

    /*
        Actually allocate the poller file descriptors that we will be using, one for each of our CPU's.
    */
    poller_fds = calloc(num_cpus, sizeof(*poller_fds));
    if (!poller_fds)
    {
        return LIBBPF_PERF_EVENT_ERROR;
    }

    /*
        Once we have our poller file descriptors allocated lets configure them to watch for events on our pre-created perf event file descriptors
        from the call to 'setup_event_watchers', specifically looking for POLLIN events (new data coming in on the perf event file descriptor).
    */
    for (i = 0; i < num_cpus; i++)
    {
        poller_fds[i].fd = perf_event_fds[i];
        poller_fds[i].events = POLLIN;
    }

    /*
        Then we just loop over calls to 'poll' waiting for events to come in on the perf event queues, until we exit.
    */
    while (run)
    {
        /*
            Call poll to handle waiting for events, and we pass in the poller_fds we created above, the number of cpu's we are watching for events from, and a timeout
            of 1000ms.
        */
        poll(poller_fds, num_cpus, 1000);
        for (i = 0; i < num_cpus; i++)
        {
            /*
                We need to check each one of the poller_fds to see which one has events to read from, you could bypass this issue by using epoll instead of standard poll.
            */
            if (!poller_fds[i].revents)
                continue;

            /*
                Given we have some events for the perf event descriptor in question we hand off its associated mmap region to the call 'bpf_perf_event_read_simple', along with 
                some metadata surrounding the mmap region so that the call knows the bounds of the region in question. We then pass in a function 'bpf_perf_event_print' which is
                called for each perf event that has been placed into the mmap region, and lastly a piece of private_data in this case the cpu id which is also passed directly into 
                the our 'bpf_perf_event_print' calls.
            */
            enum bpf_perf_event_ret ret = bpf_perf_event_read_simple(perf_event_mmaps[i],
                                                                     page_count * page_size,
                                                                     page_size, &buf, &len,
                                                                     bpf_perf_event_print,
                                                                     &i);
            
            /*
                In the event of an error during the read process we should break and shutdown.
            */
            if (ret != LIBBPF_PERF_EVENT_CONT)
                break;
        }
    }

    free(buf);
    free(poller_fds);

    return EXIT_OK;
}

/*
    'setup_event_watchers' handles creating and configuring the event rings that we will be using to look at and parse data passed up from the kernel.
    In order to properly do this we need to do a few things so that we can access the correct memory and file descriptors responsible for handling the data
    transfer.

    We need to call 'perf_event_open' which will handle taking in a filled out 'perf_event_attr' struct and in our case a CPU id, and will return a file descriptor
    that will allow us to poll for new waiting events from the kernel.

    Once we have the file descriptor we then pass that off to our 'samples' map in the XDP program so that when it goes to pass off sampled data it has a place to do 
    so. And the last thing we will need to do is create a MMAP region for the actual packet data to reside between when it was handed off from the kernel and this 
    application has a chance to pull the data in for parsing.
*/
static int setup_event_watchers(int map_fd, int num_cpus)
{
    /*
        We need some storage variables for use in setting up the variopus mmap regions.
    */
    int mmap_size;

    page_size = getpagesize();
    mmap_size = page_size * (page_count + 1);

    /*
        This 'perf_event_attr' handles configuring our user space perf event handlers so that we can pull data from the XDP program.

        Specifically we have to use the following configurations in order to properly handle eBPF events.
            - 'sample_type' nees to be 'PERF_SAMPLE_RAW' so that we can get direct access to the packet data without interpolation.
            - 'type' needs to be 'PERF_TYPE_SOFTWARE' because we are generating and viewing perf events from a software application and not some hardware device.
            - 'config' needs to be 'PERF_COUNT_SW_BPF_OUTPUT' so that we tell the perf event subsystem that we are viewing data generated from a BPF based application.
            - 'wakeup_events' is set to 1 here so that we are notified of every event emitted by the XDP application. We could change this to reduce the number of times,
                our poller is woken up.
    */
    struct perf_event_attr attr = {
        .sample_type = PERF_SAMPLE_RAW,
        .type = PERF_TYPE_SOFTWARE,
        .config = PERF_COUNT_SW_BPF_OUTPUT,
        .wakeup_events = 1,
    };

    /*
        Since our XDP application is sending perf events per CPU we need to watch for events for each CPU that could be triggering, that being said there is no
        guarantee that they will all fire as it would be completely dependant on your hardware/networking setup. In fact we will only see a single CPU fire in this 
        workshop because we have a single network interface queue and therefore cpu operating our XDP program.
    */
    for (int i = 0; i < num_cpus; i++)
    {
        /*
            First off we call 'syscall_perf_event_open' with the 'perf_event_attr' struct and the cpu id for this iteration to generate a file descriptor we can use for polling
            for perf events.
        */
        perf_event_fds[i] = syscall_perf_event_open(&attr, i);
        if (perf_event_fds[i] < 0)
        {
            printf("ERR: Failed to open perf event fd for cpu %d err(%d): %s\n",
                   i, errno, strerror(errno));
            return EXIT_FAIL_GENERIC;
        }

        /*
            We then hand off the created file descriptor to the 'samples' map we setup in the XDP program so that when we go to call 'bpf_perf_event_output' the correct file descriptor
            can be notified.
        */
        if (bpf_map_update_elem(map_fd, &i, &perf_event_fds[i], 0) != 0)
        {
            printf("ERR: Failed to update perf event map for cpu %d with fd %d err(%d): %s\n",
                   i, perf_event_fds[i], errno, strerror(errno));
            return EXIT_FAIL_XDP_MAP_UPDATE;
        }

        /*
            We need to call 'ioctl' to enable the new file descriptor to actually start receiving events.
        */
        ioctl(perf_event_fds[i], PERF_EVENT_IOC_ENABLE, 0);

        /*
            So now that we have a fully configured event file descriptor we need to create the mmap region and have it associated with the new file descriptor.
        */
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
