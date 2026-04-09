#include "PtraceConnectionTracker.h"

PtraceConnectionTracker::PtraceConnectionTracker(pid_t pid, std::unique_ptr<DataConsumerFactory> factory)
    : root_pid(pid) {
    this->factory = std::move(factory);
}

void PtraceConnectionTracker::tracee_memcpy(pid_t pid, uint8_t *destination, uint8_t *address, size_t len) const {
    for (size_t i = 0; i < (len + sizeof(long) - 1) / sizeof(long); i++) {
        long word = ptrace(PTRACE_PEEKDATA, pid, address + i * sizeof(long), 0);
        memcpy(destination + i * sizeof(long), &word, std::min(sizeof(long), len - i * sizeof(long)));
    }
}

void PtraceConnectionTracker::handle_syscall_exit(pid_t pid, TraceeState &ts) {
    auto result = static_cast<long>(ts.regs.rax);
    if (result == -1) return;

    switch (ts.pending_syscall) {
        case SYS_connect:
            tracee_connect(pid, ts.tgid, ts.regs);
            break;
        case SYS_sendto:
        case SYS_write:
            tracee_read_send(pid, ts.tgid, ts.regs, Direction::Out);
            break;
        case SYS_read:
        case SYS_recvfrom:
            tracee_read_send(pid, ts.tgid, ts.regs, Direction::In);
            break;
        case SYS_recvmsg:
            tracee_recvmsg_sendmsg(pid, ts.tgid, ts.regs, Direction::In);
            break;
        case SYS_sendmsg:
            tracee_recvmsg_sendmsg(pid, ts.tgid, ts.regs, Direction::Out);
            break;
        case SYS_close:
            tracee_close(pid, ts.tgid, ts.regs);
            break;
        default:
            break;
    }
    removed_finished();
}

void PtraceConnectionTracker::tracee_read_send(pid_t pid, pid_t tgid,
                                                const struct user_regs_struct &regs, Direction dir) {
    int socket = static_cast<int>(regs.rdi);
    auto buffer_ptr = reinterpret_cast<uint8_t *>(regs.rsi);
    auto buffer_len = static_cast<ssize_t>(regs.rax);

    if (buffer_len <= 0) return;

    auto connection = streams.find(stream_key(tgid, socket));
    if (connection == streams.end()) return;

    auto buffer = new uint8_t[buffer_len];
    tracee_memcpy(pid, buffer, buffer_ptr, buffer_len);

    if (dir == Direction::In) {
        connection->second->read(buffer, buffer_len);
    } else {
        connection->second->write(buffer, buffer_len);
    }

    delete[] buffer;
}

void PtraceConnectionTracker::tracee_recvmsg_sendmsg(pid_t pid, pid_t tgid,
                                                      const struct user_regs_struct &regs, Direction dir) {
    int socket = static_cast<int>(regs.rdi);
    auto message_ptr = reinterpret_cast<uint8_t *>(regs.rsi);
    auto sent = static_cast<ssize_t>(regs.rax);

    if (sent <= 0) return;

    struct msghdr message = {};
    tracee_memcpy(pid, reinterpret_cast<uint8_t *>(&message), message_ptr, sizeof(message));

    auto buffers = new struct iovec[message.msg_iovlen];
    for (size_t i = 0; i < message.msg_iovlen; i++) {
        tracee_memcpy(pid, reinterpret_cast<uint8_t *>(buffers + i),
                      reinterpret_cast<uint8_t *>(message.msg_iov + i), sizeof(*buffers));
    }
    message.msg_iov = buffers;

    auto buffer = new uint8_t[sent];
    size_t copied = 0;
    for (size_t i = 0; i < message.msg_iovlen; i++) {
        size_t to_copy = std::min(sent - copied, message.msg_iov[i].iov_len);
        if (to_copy == 0) break;
        tracee_memcpy(pid, buffer + copied, reinterpret_cast<uint8_t *>(message.msg_iov[i].iov_base), to_copy);
        copied += to_copy;
    }

    auto connection = streams.find(stream_key(tgid, socket));
    if (connection != streams.end()) {
        if (dir == Direction::In) {
            connection->second->read(buffer, sent);
        } else {
            connection->second->write(buffer, sent);
        }
    }

    delete[] buffer;
    delete[] buffers;
}

void PtraceConnectionTracker::tracee_close(pid_t pid, pid_t tgid, const struct user_regs_struct &regs) {
    auto fd = static_cast<int>(regs.rdi);
    auto it = streams.find(stream_key(tgid, fd));
    if (it == streams.end()) return;
    streams.erase(it);
}

void PtraceConnectionTracker::tracee_connect(pid_t pid, pid_t tgid, const struct user_regs_struct &regs) {
    auto fd = static_cast<int>(regs.rdi);
    auto address_remote_ptr = reinterpret_cast<uint8_t *>(regs.rsi);
    auto address_len = static_cast<socklen_t>(regs.rdx);

    struct sockaddr_storage storage = {};
    tracee_memcpy(pid, reinterpret_cast<uint8_t *>(&storage), address_remote_ptr, address_len);
    auto address = reinterpret_cast<struct sockaddr *>(&storage);

    if (address->sa_family != AF_INET && address->sa_family != AF_INET6) return;

    if (!this->filtered_ports.empty()) {
        if (address->sa_family == AF_INET &&
            this->filtered_ports.contains(ntohs(((struct sockaddr_in *) address)->sin_port))) return;
        if (address->sa_family == AF_INET6 &&
            this->filtered_ports.contains(ntohs(((struct sockaddr_in6 *) address)->sin6_port))) return;
    }

    auto decryptor = this->factory->create(tgid);
    std::memcpy(reinterpret_cast<uint8_t *>(&decryptor->destination_address),
                reinterpret_cast<uint8_t *>(&address), address_len);
    streams.insert(std::make_pair(stream_key(tgid, fd), std::move(decryptor)));
}

void PtraceConnectionTracker::run() {
    long opts = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEFORK |
                PTRACE_O_TRACEVFORK | PTRACE_O_TRACECLONE;
    abort_on_error(ptrace(PTRACE_SEIZE, root_pid, 0, opts));
    abort_on_error(ptrace(PTRACE_INTERRUPT, root_pid));

    int status;
    abort_on_error(waitpid(root_pid, &status, 0));
    tracees[root_pid] = {.tgid = root_pid};
    abort_on_error(ptrace(PTRACE_SYSCALL, root_pid, 0, 0));

    while (!tracees.empty()) {
        pid_t wpid = waitpid(-1, &status, __WALL);
        if (wpid == -1) break;

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            tracees.erase(wpid);
            continue;
        }

        if (!WIFSTOPPED(status)) {
            ptrace(PTRACE_SYSCALL, wpid, 0, 0);
            continue;
        }

        unsigned int event = static_cast<unsigned int>(status >> 16) & 0xff;

        // Handle fork/vfork/clone events: register the new child
        if (event == PTRACE_EVENT_FORK || event == PTRACE_EVENT_VFORK ||
            event == PTRACE_EVENT_CLONE) {
            unsigned long new_pid;
            ptrace(PTRACE_GETEVENTMSG, wpid, 0, &new_pid);

            auto parent_it = tracees.find(wpid);
            pid_t parent_tgid = (parent_it != tracees.end()) ? parent_it->second.tgid : wpid;

            // Clones (threads) share the parent's tgid; forks get their own
            pid_t child_tgid = (event == PTRACE_EVENT_CLONE) ? parent_tgid : static_cast<pid_t>(new_pid);
            tracees[static_cast<pid_t>(new_pid)] = {.tgid = child_tgid};

            std::cerr << "New " << (event == PTRACE_EVENT_CLONE ? "thread" : "process")
                      << " " << new_pid << " (tgid " << child_tgid << ")" << std::endl;

            ptrace(PTRACE_SYSCALL, wpid, 0, 0);
            continue;
        }

        // Ensure we know about this pid (child may stop before parent's event)
        if (tracees.find(wpid) == tracees.end()) {
            tracees[wpid] = {.tgid = wpid};
        }

        auto &ts = tracees[wpid];
        int sig = WSTOPSIG(status);

        if (sig & 0x80) {
            // Syscall stop (PTRACE_O_TRACESYSGOOD sets bit 7)
            if (ptrace(PTRACE_GETREGS, wpid, 0, &ts.regs) == -1) {
                // Process may have exited between waitpid and GETREGS
                ptrace(PTRACE_SYSCALL, wpid, 0, 0);
                continue;
            }

            if (ts.at_entry) {
                ts.pending_syscall = static_cast<int>(ts.regs.orig_rax);
                ts.at_entry = false;
            } else {
                handle_syscall_exit(wpid, ts);
                ts.at_entry = true;
            }

            ptrace(PTRACE_SYSCALL, wpid, 0, 0);
        } else {
            // Non-syscall stop: deliver real signals, suppress ptrace-internal ones
            int inject_sig = (sig != SIGTRAP && sig != SIGSTOP) ? sig : 0;
            ptrace(PTRACE_SYSCALL, wpid, 0, inject_sig);
        }
    }
}

void PtraceConnectionTracker::removed_finished() {
    for (auto it = streams.cbegin(); it != streams.cend();) {
        if (it->second->is_finished()) {
            streams.erase(it++);
            continue;
        }
        it++;
    }
}

void PtraceConnectionTracker::filter_port(uint16_t port) {
    this->filtered_ports.insert(port);
}
