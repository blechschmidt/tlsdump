#ifndef TLSDUMP_PTRACECONNECTIONTRACKER_H
#define TLSDUMP_PTRACECONNECTIONTRACKER_H

#include "Direction.h"
#include "TlsDecryptor.h"
#include "util.h"
#include "DataConsumerFactory.h"

#include <unordered_map>

#include <sys/ptrace.h>
#include <sys/syscall.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <unordered_set>


class PtraceConnectionTracker {
    struct TraceeState {
        struct user_regs_struct regs = {};
        bool at_entry = true;
        int pending_syscall = -1;
        pid_t tgid = 0; // thread group leader PID (process PID for fd namespace)
    };

    pid_t root_pid;
    std::unordered_map<pid_t, TraceeState> tracees;
    std::unordered_map<uint64_t, std::unique_ptr<DataConsumer>> streams;
    std::unordered_set<uint16_t> filtered_ports;
    std::unique_ptr<DataConsumerFactory> factory;

    static uint64_t stream_key(pid_t tgid, int fd) {
        return (static_cast<uint64_t>(static_cast<uint32_t>(tgid)) << 32) |
               static_cast<uint32_t>(fd);
    }

public:
    explicit PtraceConnectionTracker(pid_t pid, std::unique_ptr<DataConsumerFactory> factory);

    void filter_port(uint16_t port);

    void run();

private:
    void tracee_memcpy(pid_t pid, uint8_t *destination, uint8_t *address, size_t len) const;

    void handle_syscall_exit(pid_t pid, TraceeState &ts);

    void tracee_connect(pid_t pid, pid_t tgid, const struct user_regs_struct &regs);

    void tracee_close(pid_t pid, pid_t tgid, const struct user_regs_struct &regs);

    void tracee_read_send(pid_t pid, pid_t tgid, const struct user_regs_struct &regs, Direction dir);

    void tracee_recvmsg_sendmsg(pid_t pid, pid_t tgid, const struct user_regs_struct &regs, Direction dir);

    void removed_finished();
};

#endif //TLSDUMP_PTRACECONNECTIONTRACKER_H
