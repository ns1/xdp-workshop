# DDoS mitigation made easy with XDP and eBPF
This workshop's purpose is to give fully functional and annotated examples of how to build, run, and maintain XDP programs. The examples range from a simple hello world type example to a TC bit auto responder and packet sampling application. By the end of this workshop you should have all of the information and experience to design and implement purpose built XDP programs for your specific usecases.

## Directory Structure
The directory structure is broken down into multiple ordered examples described bellow.

### 00-environment
This directory contains a helper script for working with the test lab VM and for creating an environment for testing the various exercises.

### 01-helloworld
This section goes through the various aspects of a XDP program, and how one can interact with and maintain XDP programs using tooling such as `iproute2`.

### 02-stats
In this section we will be diving into the basics of leveraging BPF map objects to export simple data from an XDP program to a userspace application. We will be diviing into a new tool in this section called `bpftool`

### 03-pinning
Now that we have an idea of how to work with BPF maps leveraging existing applications we are going to dive into how we can programatically interact with and manage BPF map life cycle leveraging `libbpf`.

### 04-xdpfw
We are going to dig into various advanced types of BPF map objects and a complex XDP program for managing layer 2-4 packet blacklists. Specifically digging into how to leverage hash and lpm_trie maps to manage complex matching of packets.

### 05-sampler
Now that we have a solid idea of how to leverage and manage XDP programs and the BPF maps that power them we are going to dive into a different type of BPF map to export entire packets from kernel space to user space for deep packet introspection and offline analysis.

### 06-tcbit
In this final exercise we are going to dive into `XDP_TX` and explore the capability for XDP programs to transmit packets.

### common
This contains various common headers and scripts that are used throughout the workshop to either hide irrelevant or redundant code.

We will touch on the pieces in this directory as needed.

### lab
This contains all of the documentation on the testing harness used throughout this workshop. As well as the steps to create the harness from scratch on your own, or to modify it to suit your needs in the future.

### libbpf
This is a submodule pointing at [the github based mirror of libbpf](https://github.com/libbpf/libbpf), which is leveraged in the various exercises throughout this workshop. In order to enable the userspace applications to manage the XDP programs and BPF maps we will be working with.

## Acknowledgements
I want to extend a sincere thank you to the kernel development team and all of those that have contributed to the development and implementation of the cBPF, eBPF, and XDP subsystems that have enabled this technology to thrive.

In order to make this workshop a success I leveraged a myriad of different source material and most notably leveraged the kernel sources itself and even some of their code to enable the various exercises.

Other then the kernel itself I leveraged:
- https://prototype-kernel.readthedocs.io/en/latest/index.html
- https://cilium.io/
- https://github.com/iovisor/bcc
- https://github.com/xdp-project/xdp-tutorial

I also leveraged various other talks, blogs and posts on the internet throughout the development of this workshop. 
