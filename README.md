# TLSDump
## Ptrace-based TLS 1.2 master secret extractor

Approaches to automatically extract TLS keys from memory have been described in the
[TeLeScope](https://conference.hitb.org/hitbsecconf2016ams/wp-content/uploads/2015/11/D1T1-Radu-Caragea-Peering-into-the-Depths-of-TLS-Traffic-in-Real-Time.pdf),
[TLSkex](https://www.sciencedirect.com/science/article/pii/S1742287616300081) and
[DroidKex](https://www.sciencedirect.com/science/article/pii/S1742287618301890) publications. 
Unfortunately, their source code has never been released. This is a **proof-of-concept implementation** of a TLS 1.2 key
extractor based on [ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html). It is not very sophisticated and does
not implement many possible optimizations. TLS 1.3 is not supported.

## Usage
Compilation requires [CMake](https://cmake.org/). First clone the repository, `cd` into it, then run:
```
cmake . && make
```

TLSDump will output the key in [SSLKEYLOGFILE Format](https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html).

The following will output the key material for the `curl` command:
```
tlsdump -- curl --tlsv1.2 --tls-max 1.2 --http1.1 https://example.org
```

Alternatively, the `-w` option can be used to specify a file which to write the key material to:
```
tlsdump -w /tmp/sslkeylogfile.txt -- curl --tlsv1.2 --tls-max 1.2 --http1.1 https://example.org
```

## How does it work?
TLSDump performs syscall hooking using `ptrace`. Upon a call to `connect`, it will remember the returned file
descriptor. TLSDump will then monitor this file descriptor for TLS handshakes by hooking
the `write`, `sendto`, and `sendmsg` syscalls, as well as their `read`, `recvfrom`, and `recvmsg` counterparts. Once the
completion of a handshake is detected, TLSDump will pause the target program, extract its memory and perform an
exhaustive search over the memory by testing whether the current search position is the start of a TLS master secret. To
this end, decryption functions copied from the Wireshark project are used.

## Why?
Sometimes you might want to inspect the TLS traffic of closed-source applications without having to tediously reverse
engineer them.

## TLS 1.3
TLS 1.3 is currently not supported. However, adding support for TLS 1.3 should be possible as follows: First, identify the `CLIENT_HANDSHAKE_TRAFFIC_SECRET` by trying to decrypt the `Handshake Protocol: Finished` message through an exhaustive search in memory for the key. Having identified this secret, an exhaustive search for the `CLIENT_TRAFFIC_SECRET_0` should be possible.

## Limitations
* A target program can easily evade this approach by obfuscating the keys stored in memory. A simple XOR would suffice.
* The current implementation does not support processes that perform fork operations.
