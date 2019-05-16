# Hello World
This exercise digs into the overall architecture of XDP and options for interacting and debugging XDP programs in the wild, as well as during development. The key here is to look at the file `helloworld_kern.c` which has a few key pieces of information. Lets break them down.

## `bpf_debug`
This macro is a helper based around the included function `bpf_trace_printk` which allows an XDP, or any BPF program, to print messages to the pipe at `/sys/kernel/tracing/trace_pipe`. This function allows for basic formating as well similar to `printf`. However this comes with limitations which we will discuss in depth, but the high level is that you are limited in the amount of memory you can allocate as well as how many options may be used at a time.

In order to use this functionality attach an XDP program that leverages this macro and try running:

```
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
```

> Note that the output of this will have all XDP programs outputing interleaved log messages so this is best used for development and debugging purposes only.

## `SEC("")`
This macro is used to tell the `elf_bpf` loader and various utilities surrounding it what each function, map, license is and where to place it in the resulting compiled `elf_bpf` file. This is very important for a few key reasons:

- It allows for specifying multiple XDP programs in a single compiled object that can all be loaded/attached separately.
  - It also allows for implementing tail calls which will be discussed later on in the workshop.
- It allows for specifying an arbitray number of BPF maps, in the `SEC("maps")` section.
- It allows for specifying the license and optionally the version of the XDP program, in the `SEC("license")` and `SEC("version")` sections respectively.

Overall sections allow for segregating your XDP programs and allow for options in terms of what is loaded and how it is interacted with.

## Return codes
An XDP program has a highly specific set of return codes that you **must** return in order for the XDP program to operate properly. They are listen in the kernel headers and bellow:

```
    enum xdp_action {
        XDP_ABORTED = 0,
        XDP_DROP,
        XDP_PASS,
        XDP_TX,
        XDP_REDIRECT,
    };
```

Each one of the above actions serve a specific intention that the writer of the XDP porgram intends to happen to packets after passing through the program.

### `XDP_ABORTED`
This should be used when an XDP program encounters an exceptional case when parsing/mangling packets. When a program returns `XDP_ABORTED` it signals that packet should be dropped, but also incremenents an internal kernel counter `xdp:xdp_exception` which can be viewed via the `perf` tool from bcc.

An example of viewing this counter is:

```
$ sudo perf record -a -e xdp:* sleep 10
$ sudo perf script
```

The above will output a list of all the various XDP programs that returned exceptions, their ID's and how often the case was hit.

### `XDP_DROP`
This does exactly what one would expect it to do, and drops the packet out right. The key difference between `XDP_DROP` and `XDP_ABORTED` is that the former does not increment the exception counter like the latter does.

If you are building a firewall or a DDoS mitigation tool, this will be the return code you use for any unwanted network traffic.

### `XDP_PASS`
This does the exact opposite of `XDP_DROP` and passes the packet in question off to the kernel for further processing downstream. To be clear, returning `XDP_PASS` does not mean that the resulting packet will be ultimately accepted by the system as a whole. It could very well be dropped down the line by other filtering technologies like iptables and user space applications.

### `XDP_TX`
This is an advanced return code that allows for "bouncing" packets back out the network interface they came in on. This parcitcular return code can be **dangerous** if not implemented correctly, and has the potential for creating packet loops and other unsavory conditions. To that end, we will dive into `XDP_TX` in depth in the advanced section of this workshop.

### `XDP_REDIRECT`
This is another advanced and relatively new return code for XDP programs, and can be used similarly to how one would use `XDP_TX`. However unlike `XDP_TX` it can be used to redirect packets to different network interfaces, CPU's, or even completely out of the kernel to user space applications leveraging `AF_XDP` sockets.

We will not be diving in this return code for this workshop.

## Building and Attaching/Detaching XDP programs
In order to build an XDP program you will need some tooling to compile the C code into a `elf_bpf` object. In this workshop we are going to be leveraging `clang` along side `llvm` to generate the proper output files.

In this directory there is a `Makefile` that actually sources a common file in `common/makerules` to do the compilation steps. But for sake of brevity its been reproduced bellow:

```
clang -S \
    -target bpf \
    -D __BPF_TRACING__ \
    "-I../../common/headers/" \
    "-I../../libbpf/src/root/usr/include/" \
    "-I/usr/include/x86_64-linux-gnu" \
    -Wall \
    -Wno-compare-distinct-pointer-types \
    -O2 -emit-llvm -c -g \
    -o helloworld_kern.ll helloworld_kern.c
llc -march=bpf -filetype=obj -o helloworld_kern.o helloworld_kern.ll
```

Instead of typing out the above you can simply run `make` in this directory and the `Makefile` will handle compiling the program for you.

Once you have successfully compiled your XDP program, there are many options available for attaching and detaching XDP programs to/from a given network interface. The two we will be focusing on throughout this workshop are `iproute2` and `libbpf`, but for this exercise we will be using `iproute2` specifically.

To use `iproute2` to attach an XDP program use the following syntax:
```
$ sudo ip link set dev ${device name} xdp obj ${object file} sec ${section name}
```

Where in the above `${device name}` is the name of the interface that you wish to attach the given xdp program to as seen from the output of `ip link`. The `${object file}` parameter is the path to the file generated from the `make` or compile commands above, and this file generally ends with the suffix `_kern.o`. The `${section name}` parameter is the `SEC("")` section you wish to attach, which can be left off and the first non `SEC("maps")`/`SEC("license")`/`SEC("version")` section listed in the file will be used.

To use `iproute2` to **detach** an XDP program use the following syntax:

```
$ sudo ip link set dev ${device name} xdp off
```

Where in the above `${device name}` is the name of the interface that you have an attached XDP program you wish to disable.

## Lets get our hands dirty

So for our first test lets run these commands from this directory:
```
$ make
clang -S \
    -target bpf \
    -D __BPF_TRACING__ \
     "-I../../common/headers/" "-I../../libbpf/src/root/usr/include/" "-I/usr/include/x86_64-linux-gnu" \
    -Wall \
        -Wno-compare-distinct-pointer-types \
    -O2 -emit-llvm -c -g -o helloworld_kern.ll helloworld_kern.c
llc -march=bpf -filetype=obj -o helloworld_kern.o helloworld_kern.ll

$ sudo ip link set dev lo xdp obj helloworld_kern.o sec xdp_pass
```

Congratulations! You just compiled and attached your first XDP program. Now lets see what we have here, to verify the program is attached you can re-run the `ip link` command and the interface, in this case `lo`, will show a new line looking something like `prog/xdp id 51`.

To view the `bpf_debug` output from the attached program go ahead and run:
```
$ sudo cat /sys/kernel/debug/tracing/trace_pipe
```

and in a separate terminal run:

```
ping localhost
```

In the first terminal where you ran `sudo cat` you should start seeing output akin to:
```
ping-11851 [001] ..s1 44513.843390: 0: Passing packet to kernel!
```

We not only built and attached a custom XDP program but we can verify its working expected using debug tooling! That being said, now that we are done with this test run the following to detach the XDP program from the interface:

```
$ sudo ip link set dev lo xdp off
```

### Extra Credit
Take a look at attaching the other sections from this compiled object, `xdp_abort` and `xdp_drop`, and view what happens to the `ping` and `cat` commands we had running before.