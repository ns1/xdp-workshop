# DDoS mitigation made easy with XDP and eBPF
This work shop consists of three parts and is broken down between basic, intermediate, and advanced tutorials that will walk through everything from a "Hello World" example to advanced topics like automatically responding to traffic flows and honey potting malicious traffic.

## Directory Structure
The directory structure is broken down into four main parts as well as a lab setup section.

### 00-environment
This direectory contains a helper script for working with the test lab VM and for creating an environment for testing the various exercises.

### 01-basic
This section goes through the various aspects of a XDP program.

Key topics:
* Basic structure and layout of a XDP program.
* What you can and can't do with a XDP program.
* An overview of BPF map objects and how to use them to make dynamic XDP programs.

### 02-intermediate
This will be the longest section of the workshop and contains the steps to construct a basic layer 2, 3, and 4 firewall.

Key topics:
* Managing BPF map data from userspace and leveraging those changes on the fly in XDP.
* Leveraging BPF_MAP_TYPE_LPM_TRIE maps to black list IPv4 and IPv6 address prefixes.
* Leveraging BPF_MAP_TYPE_LPM_HASH maps to black list source/destination ports for UDP/TCP.

### 03-advanced
This will be a short section explaining the utility and limitations of `XDP_TX` by walking through a TC bit autoresponder to handle UDP based DNS DDoS attacks. As well as a XDP program to honeypot malicious traffic flows for further introspection.

Key Topics:
* How `XDP_TX` works and what it is and isn't capable of.
* How to manipulate packet data in real time within an XDP program.

### common
This contains various common headers and scripts that are used throughout the workshop to either hide irrelevant code or redundant code.

We will touch and the pieces in this directory as needed.

### lab
This contains all of the documentation on the testing harness used throughout this workshop. As well as the steps to create the harness from scratch on your own, or to modify it to suit your needs in the future.

### libbpf
This is a submodule pointing at [the github based mirror of libbpf](https://github.com/libbpf/libbpf), which is leveraged in the various exercises throughout this workshop.
