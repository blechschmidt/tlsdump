# TLSDump
## Ptrace-based TLS 1.2/1.3 key extractor

Approaches to automatically extract TLS keys from memory have been described in the
[TeLeScope](https://conference.hitb.org/hitbsecconf2016ams/wp-content/uploads/2015/11/D1T1-Radu-Caragea-Peering-into-the-Depths-of-TLS-Traffic-in-Real-Time.pdf),
[TLSkex](https://www.sciencedirect.com/science/article/pii/S1742287616300081) and
[DroidKex](https://www.sciencedirect.com/science/article/pii/S1742287618301890) publications. 
Unfortunately, their source code has never been released. This is a **proof-of-concept implementation** of a TLS 1.2/1.3 key
extractor based on [ptrace](https://man7.org/linux/man-pages/man2/ptrace.2.html). It is not very sophisticated and does
not implement many possible optimizations.

## Usage
Compilation requires [CMake](https://cmake.org/) and the development libraries for GLib and libgcrypt. First clone the repository, `cd` into it, then run:
```
cmake . && make
```

TLSDump will output the key in [SSLKEYLOGFILE Format](https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html).

```
tlsdump [options] [--] command [args...]
tlsdump [options] pid
tlsdump --extract <dir> [-w keylogfile]
```

### Options

| Option | Description |
|---|---|
| `-w <file>` | Write key material to the specified file instead of stdout. |
| `--defer <dir>` | Deferred capture mode. Dump TLS metadata and process memory to the directory instead of searching for keys inline. The key search can be performed later using `--extract`. |
| `--extract <dir>` | Offline extraction mode. Read dump files from the directory and search for TLS keys. Does not trace any process. Can be run on a different machine than the capture. |
| `--` | Separator between tlsdump options and the command to execute. Optional if the command does not start with a dash or a number. |

### Examples

Extract keys inline while running curl (TLS 1.2):
```
tlsdump -- curl --tlsv1.2 --tls-max 1.2 --http1.1 https://example.org
```

Extract keys inline (TLS 1.3):
```
tlsdump curl --http1.1 https://example.org
```

Write key material to a file:
```
tlsdump -w /tmp/sslkeylogfile.txt -- curl --http1.1 https://example.org
```

Attach to a running process by PID:
```
tlsdump -w /tmp/sslkeylogfile.txt 12345
```

Deferred two-stage capture and extraction:
```
# Stage 1: Capture (fast, no key search)
tlsdump --defer /tmp/tlsdumps -- curl --http1.1 https://example.org

# Stage 2: Extract keys offline (can be on a different machine)
tlsdump --extract /tmp/tlsdumps -w /tmp/sslkeylogfile.txt
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
TLS 1.3 is supported. The approach works as follows: First, the `CLIENT_HANDSHAKE_TRAFFIC_SECRET` is identified by trying to decrypt the client's `Finished` message through an exhaustive search in memory for the key. Then, `CLIENT_TRAFFIC_SECRET_0`, `SERVER_HANDSHAKE_TRAFFIC_SECRET`, and `SERVER_TRAFFIC_SECRET_0` are each identified by decrypting their respective encrypted records using candidate traffic secrets found in memory. Keys are derived from candidate secrets using HKDF-Expand-Label (RFC 8446).

## Limitations
* A target program can easily evade this approach by obfuscating the keys stored in memory. A simple XOR would suffice.
