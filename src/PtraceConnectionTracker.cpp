#include "PtraceConnectionTracker.h"

bool PtraceConnectionTracker::tracee_finish_syscall() {
    abort_on_error(ptrace(PTRACE_SYSCALL, pid, 0, 0));
    abort_on_error(waitpid(pid, &status, 0));
    abort_on_error(ptrace(PTRACE_GETREGS, pid, 0, &state));

    return cast_syscall_result<long>() != -1;
}

void PtraceConnectionTracker::tracee_read_send(Direction dir) {
    if (!tracee_finish_syscall()) {
        return;
    }

    struct read_send_data call = {
            .socket = static_cast<int>(state.rdi),
            .buffer = reinterpret_cast<uint8_t *>(state.rsi),
            .buffer_len = static_cast<ssize_t>(state.rax)
    };

    if (call.buffer_len < 0) {
        return;
    }

    // No connect recorded.
    auto connection = streams.find(call.socket);
    if (connection == streams.end()) {
        return;
    }

    auto buffer = new uint8_t[call.buffer_len];
    tracee_memcpy(buffer, call.buffer, call.buffer_len);
    call.buffer = buffer;

    if (dir == Direction::In) {
        connection->second->read(call.buffer, call.buffer_len);
    } else {
        connection->second->write(call.buffer, call.buffer_len);
    }

    delete[] buffer;
}

void PtraceConnectionTracker::tracee_recvmsg_sendmsg(Direction dir) {
    if (!tracee_finish_syscall()) {
        return;
    }

    struct read_send_data call = {};
    call.socket = static_cast<int>(state.rdi);
    struct msghdr message = {};
    auto message_ptr = reinterpret_cast<uint8_t *>(state.rsi);
    auto sent = static_cast<ssize_t>(state.rax);
    call.buffer_len = sent;

    if (sent < 0) {
        return;
    }

    tracee_memcpy(reinterpret_cast<uint8_t *>(&message), message_ptr, sizeof(message));

    auto buffers = new struct iovec[message.msg_iovlen];
    for (size_t i = 0; i < message.msg_iovlen; i++) {
        tracee_memcpy(reinterpret_cast<uint8_t *>(buffers + i), reinterpret_cast<uint8_t *>(message.msg_iov + i),
                      sizeof(*buffers));
    }
    message.msg_iov = buffers;

    auto buffer = new uint8_t[sent];
    size_t copied = 0;
    for (size_t i = 0; i < message.msg_iovlen; i++) {
        size_t to_copy = std::min(sent - copied, message.msg_iov[i].iov_len);
        if (to_copy == 0) {
            break;
        }
        tracee_memcpy(buffer + copied, reinterpret_cast<uint8_t *>(message.msg_iov[i].iov_base), to_copy);
        copied += to_copy;
    }
    call.buffer = buffer;

    auto connection = streams.find(call.socket);
    if (connection == streams.end()) {
        return;
    }

    if (dir == Direction::In) {
        connection->second->read(call.buffer, call.buffer_len);
    } else {
        connection->second->write(call.buffer, call.buffer_len);
    }
}

void PtraceConnectionTracker::tracee_close() {
    if (!tracee_finish_syscall()) {
        return;
    }
    auto fd = static_cast<int>(state.rdi);
    auto it = streams.find(fd);
    if (it == streams.end()) {
        return;
    }
    streams.erase(it);
}

void PtraceConnectionTracker::tracee_connect() {
    if (!tracee_finish_syscall()) {
        return;
    }

    auto fd = static_cast<int>(state.rdi);
    auto address_remote_ptr = reinterpret_cast<uint8_t *>(state.rsi);
    auto address_len = static_cast<socklen_t>(state.rdx);

    struct sockaddr_storage storage = {};

    tracee_memcpy(reinterpret_cast<uint8_t *>(&storage), address_remote_ptr, address_len);

    auto address = reinterpret_cast<struct sockaddr *>(&storage);

    // Ignore non-IP sockets.
    if (address->sa_family != AF_INET && address->sa_family != AF_INET6) {
        return;
    }

    if (!this->filtered_ports.empty()) {
        if (address->sa_family == AF_INET &&
            this->filtered_ports.contains(ntohs(((struct sockaddr_in *) address)->sin_port))) {
            return;
        }
        if (address->sa_family == AF_INET6 &&
            this->filtered_ports.contains(ntohs(((struct sockaddr_in6 *) address)->sin6_port))) {
            return;
        }
    }
    auto decryptor = this->factory->create(pid);
    std::memcpy(reinterpret_cast<uint8_t *>(&decryptor->destination_address),
                reinterpret_cast<uint8_t *>(&address), address_len);
    streams.insert(std::make_pair(fd, std::move(decryptor)));
}

void PtraceConnectionTracker::tracee_memcpy(uint8_t *destination, uint8_t *address, size_t len) const {
    for (size_t i = 0; i < (len + sizeof(long) - 1) / sizeof(long); i++) {
        long word = ptrace(PTRACE_PEEKDATA, pid, address + i * sizeof(long), 0);
        memcpy(destination + i * sizeof(long), &word, std::min(sizeof(long), len - i * sizeof(long)));
    }
}

void PtraceConnectionTracker::run() {
    abort_on_error(ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESYSGOOD));
    abort_on_error(ptrace(PTRACE_INTERRUPT, pid));

    abort_on_error(waitpid(pid, &status, 0));

    while (!WIFEXITED(status)) {
        abort_on_error(ptrace(PTRACE_SYSCALL, pid, 0, 0));
        abort_on_error(waitpid(pid, &status, 0));

        // at syscall
        if (WIFSTOPPED(status)) {

            if (WSTOPSIG(status) & 0x80) {

                abort_on_error(ptrace(PTRACE_GETREGS, pid, 0, &state));

                int syscall_no = static_cast<int>(state.orig_rax);
                switch (syscall_no) {
                    case SYS_connect:
                        tracee_connect();
                        break;
                    case SYS_sendto:
                    case SYS_write:
                        // Both syscall share the same initial three arguments: fd, buffer, len.
                        tracee_read_send(Direction::Out);
                        break;
                    case SYS_read:
                    case SYS_recvfrom:
                        // Both syscall share the same initial three arguments: fd, buffer, len.
                        tracee_read_send(Direction::In);
                        break;
                    case SYS_recvmsg:
                        tracee_recvmsg_sendmsg(Direction::In);
                        break;
                    case SYS_sendmsg:
                        tracee_recvmsg_sendmsg(Direction::Out);
                        break;
                    case SYS_close:
                        tracee_close();
                        break;
                    default:
                        tracee_finish_syscall();
                        break;
                }

                removed_finished();
            }
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

PtraceConnectionTracker::PtraceConnectionTracker(pid_t pid, std::unique_ptr<DataConsumerFactory> factory) : pid(pid) {
    this->factory = std::move(factory);
}

template<typename T>
T PtraceConnectionTracker::cast_syscall_result() {
    return static_cast<T>(state.rax);
}