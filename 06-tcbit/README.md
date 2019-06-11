# tcbit
This exercise is going to explain how to properly leverage the return code `XDP_TX` as well as discuss the various strengths and weaknesses of the implementation.

## `XDP_TX`
So what exactly is `XDP_TX` and how does it compare to the other return codes we have seen so far in this workshop. Well in a nutshell `XDP_TX` specifies that the packet being operated on currently should be retransmitted back out the **current** network device. The latter point about it being retransmitted out the current network device is very important. It means that the packet must be capable of being properly transmitted out the same interface as it came in on, i.e. MAC addressing and IP addressing must match and must be valid for the interface in question. This is in stark contrast to the return code `XDP_REDIRECT` which **can** redirect a packet out a different interface. 

This particular return code also shows one of the biggest powers of the XDP and that is the fact that it can mangle the packet in **any** way it sees fit, and in the case of this exercise we are arbitrary changing:
- MAC headers
- IP headers
- UDP headers
- DNS headers

However it comes with a caveat you have to do all of the management of those changes yourself, for instance you must handle checksumming yourself as well as if you wanted to mangle TCP (explicitly skipped in this exercise) you would potentially need to worry about handling TCP stream decoding.

